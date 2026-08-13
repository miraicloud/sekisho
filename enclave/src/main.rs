use std::{env, net::SocketAddr, path::Path};

use nautilus::NautilusContext;
use nautilus_nsm::NsmAttestor;
use sekisho_enclave::{AppConfig, app, serve};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // NSM vs. dev-mode boot switch (an internal sibling project pattern, per
    // docs/research/local-patterns.md §1.1).
    let ctx = if Path::new("/dev/nsm").exists() {
        println!("[nautilus] booting with Nitro Secure Module");
        NsmAttestor::default().into_context()?
    } else {
        println!("[nautilus] booting in local development mode");
        NautilusContext::development()
    };

    println!("[nautilus] public key: {}", ctx.public_key_hex());
    println!("[nautilus] address:    {}", ctx.sui_address());

    let config = AppConfig::load_from_env()?;
    println!(
        "[server] providers: anthropic={} openai-compatible={}",
        if config.anthropic_api_key.is_some() {
            "enabled"
        } else {
            "disabled (no anthropic_api_key)"
        },
        if config.openai_api_key.is_some() {
            "enabled"
        } else {
            "disabled (no openai_api_key)"
        },
    );
    println!("[server] config_hash: {}", hex::encode(config.config_hash));

    let addr = socket_addr()?;
    println!("[server] listening on http://{addr}");
    serve(addr, app(ctx, config)).await
}

fn socket_addr() -> anyhow::Result<SocketAddr> {
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("PORT")
        .ok()
        .map(|value| value.parse::<u16>())
        .transpose()?
        .unwrap_or(3000);
    Ok(format!("{host}:{port}").parse()?)
}
