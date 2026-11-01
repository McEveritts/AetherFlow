use std::sync::Arc;

use aetherflow_plugin_sdk_template::{
    build_router, AetherFlowClient, PluginConfig, PLUGIN_ID, PLUGIN_NAME,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = PluginConfig::from_env();
    let addr = config.socket_addr()?;
    let client = Arc::new(AetherFlowClient::from_config(&config));
    let app = build_router(client);

    eprintln!(
        "starting AetherFlow Rust companion plugin '{}' ({}) on http://{} -> upstream {}",
        PLUGIN_NAME, PLUGIN_ID, addr, config.api_base_url
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
