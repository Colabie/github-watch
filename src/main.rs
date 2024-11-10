use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;

#[derive(Clone)]
struct GithubSecret {
    secret: SecretString,
}

#[tokio::main]
async fn main() {
    let secret = GithubSecret::get_or_generate();

    let router = Router::new()
        .route("/github-watch", post(handle_git_hook))
        .with_state(secret);

    let address = "[::]:8081";
    let listner = tokio::net::TcpListener::bind(address).await.unwrap();
    println!("[github-watch]: Info: Listening on: http://{}\n", address);
    axum::serve(listner, router).await.unwrap();
}

pub type HmacSha256 = Hmac<Sha256>;
async fn handle_git_hook(
    State(state): State<GithubSecret>,
    headers: HeaderMap,
    body: String,
) -> Result<(), (StatusCode, &'static str)> {
    let signature = hex::decode(
        headers
            .get("x-hub-signature-256")
            .ok_or((StatusCode::UNAUTHORIZED, "missing x-hub-signature-256"))?
            .as_bytes()
            .strip_prefix(b"sha256=")
            .ok_or((
                StatusCode::BAD_REQUEST,
                "could not parse x-hub-signature-256 as str",
            ))?,
    )
    .map_err(|_| (StatusCode::UNAUTHORIZED, "Couldn't decode secret"))?;

    let mut mac =
        HmacSha256::new_from_slice(state.secret.expose_secret().as_bytes()).map_err(|e| {
            eprintln!("[github-watch]: Error: Could not build mac: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An error occured validating payload",
            )
        })?;
    mac.update(body.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid secret"))?;

    println!("Hook triggered: {}", body);
    Ok(())
}

impl GithubSecret {
    const SECRET_FILE: &'static str = ".github-webhook-secret";

    fn get_or_generate() -> Self {
        use rand::{distributions::Alphanumeric, thread_rng, Rng};
        use std::fs;

        let get_secret_from_file_or_generate = || -> Result<String, std::io::Error> {
            if !fs::exists(Self::SECRET_FILE)? {
                let secret = thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(150)
                    .map(char::from)
                    .collect();

                println!("[github-watch]: Info: Copy this secret: \"{}\"", secret);
                fs::write(Self::SECRET_FILE, &secret)?;
                Ok(secret)
            } else {
                Ok(fs::read_to_string(Self::SECRET_FILE)?)
            }
        };

        let secret = get_secret_from_file_or_generate().expect("File System Perms");

        GithubSecret {
            secret: secret.into(),
        }
    }
}
