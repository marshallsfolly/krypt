//! `krypt-devmailbox [addr]`: serve a local mailbox (default 127.0.0.1:8787).

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8787".to_owned());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let (bound, task) = krypt_devmailbox::serve(listener).await?;
    println!("krypt dev mailbox on http://{bound}");
    let _ = task.await;
    Ok(())
}
