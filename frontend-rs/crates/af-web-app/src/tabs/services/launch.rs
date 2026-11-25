use crate::state::AppContext;
use af_models::APP_LAUNCH_EXCHANGE_PATH;
use af_web_core::api::ApiClient;
use leptos::prelude::GetUntracked;
use serde_json::{json, Value};
use url::Url;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use web_sys::{
    Document, HtmlAnchorElement, HtmlFormElement, HtmlInputElement, MouseEvent, Node, Window,
};

use super::helpers::field;

pub(crate) fn launch_app(
    context: AppContext,
    event: MouseEvent,
    service: &Value,
    destination: &str,
) {
    // Peer listeners forbid `/api/v1/admin/apps/launch`; open the peer's own
    // validated URL directly via the anchor without calling the local launcher.
    if context.is_remote_untracked() {
        return;
    }
    let Some(exchange) = launch_exchange(service, destination).filter(|_| context.is_admin())
    else {
        return;
    };
    let Some(popup) = web_sys::window().and_then(|window| {
        window
            .open_with_url_and_target("about:blank", "_blank")
            .ok()
            .flatten()
    }) else {
        // The original anchor remains available if window.open is blocked.
        return;
    };
    event.prevent_default();
    if popup.set_opener(&JsValue::NULL).is_err() {
        let _ = popup.close();
        context.toast(context.t("Unable to open application"), true);
        return;
    }

    let app = field(service, &["id", "slug", "process"]);
    let destination = destination.to_string();
    let session_epoch = context.session_epoch.get_untracked();
    let server_epoch = context.server_epoch.get_untracked();
    spawn_local(async move {
        let result = ApiClient
            .post(
                "/api/v1/admin/apps/launch",
                Some(&json!({ "app": app, "destination": destination })),
            )
            .await;
        if context.session_epoch.try_get_untracked() != Some(session_epoch)
            || context.server_epoch.try_get_untracked() != Some(server_epoch)
        {
            let _ = popup.close();
            return;
        }
        let navigation = match result {
            Ok(response) => match response["ticket"].as_str() {
                Some(ticket) => submit_ticket(&popup, exchange.as_str(), ticket),
                None => open_direct(&popup, &destination),
            },
            Err(error) => {
                let _ = popup.close();
                context.toast(context.t(&error.message), true);
                return;
            }
        };
        if navigation.is_err() {
            let _ = popup.close();
            context.toast(context.t("Unable to open application"), true);
        }
    });
}

fn launch_exchange(service: &Value, destination: &str) -> Option<Url> {
    let url = Url::parse(destination).ok()?;
    if url.port().is_some() || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let host = url.host_str()?;
    match url.scheme() {
        "https" => {
            let public_domain = service["public_domain"].as_str()?;
            if service["external_access_enabled"] != true
                || !host.eq_ignore_ascii_case(public_domain)
            {
                return None;
            }
            url.join(APP_LAUNCH_EXCHANGE_PATH).ok()
        }
        "http" => {
            let app = field(service, &["id", "slug", "process"]);
            if app.is_empty() || app.contains('.') {
                return None;
            }
            let expected_local = format!("{}.aether.local", app.to_ascii_lowercase());
            if !host.eq_ignore_ascii_case(&expected_local) {
                return None;
            }
            url.join(APP_LAUNCH_EXCHANGE_PATH).ok()
        }
        _ => None,
    }
}

fn popup_container(document: &Document) -> Result<Node, JsValue> {
    document
        .body()
        .map(JsCast::unchecked_into)
        .or_else(|| document.document_element().map(JsCast::unchecked_into))
        .ok_or(JsValue::NULL)
}

fn open_direct(popup: &Window, destination: &str) -> Result<(), JsValue> {
    let document = popup.document().ok_or(JsValue::NULL)?;
    // Nodes created in the popup's Document belong to the popup's JS realm, so
    // `dyn_into` (`instanceof` against the opener window's constructors) always fails.
    let link = document
        .create_element("a")?
        .unchecked_into::<HtmlAnchorElement>();
    link.set_href(destination);
    link.set_rel("noreferrer");
    popup_container(&document)?.append_child(&link)?;
    link.click();
    Ok(())
}

fn submit_ticket(popup: &Window, exchange: &str, ticket: &str) -> Result<(), JsValue> {
    let document = popup.document().ok_or(JsValue::NULL)?;
    // Nodes created in the popup's Document belong to the popup's JS realm;
    // avoid cross-realm `dyn_into` (`instanceof`) checks.
    let form = document
        .create_element("form")?
        .unchecked_into::<HtmlFormElement>();
    form.set_method("post");
    form.set_action(exchange);
    let input = document
        .create_element("input")?
        .unchecked_into::<HtmlInputElement>();
    input.set_type("hidden");
    input.set_name("ticket");
    input.set_value(ticket);
    form.append_child(&input)?;
    popup_container(&document)?.append_child(&form)?;
    form.submit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_exchange_is_limited_to_configured_public_https_links() {
        let mut service = json!({
            "public_domain": "metrics.example.com",
            "external_access_enabled": true,
        });
        assert_eq!(
            launch_exchange(&service, "https://metrics.example.com/graph?show=all")
                .unwrap()
                .as_str(),
            "https://metrics.example.com/.well-known/aetherflow/app-launch"
        );
        assert_eq!(
            launch_exchange(&service, "https://metrics.example.com/ops/netdata")
                .unwrap()
                .as_str(),
            "https://metrics.example.com/.well-known/aetherflow/app-launch"
        );
        for url in [
            "http://metrics.example.com/",
            "https://metrics.example.com:8443/",
            "https://metrics.example.com.evil.test/",
            "https://metrics.example.com@evil.test/",
            "https://127.0.0.1/",
        ] {
            assert!(launch_exchange(&service, url).is_none(), "{url}");
        }
        service["external_access_enabled"] = false.into();
        assert!(launch_exchange(&service, "https://metrics.example.com/").is_none());

        let local_service = json!({
            "id": "prometheus",
            "external_access_enabled": false,
        });
        assert_eq!(
            launch_exchange(&local_service, "http://prometheus.aether.local/graph")
                .unwrap()
                .as_str(),
            "http://prometheus.aether.local/.well-known/aetherflow/app-launch"
        );
        assert!(launch_exchange(&local_service, "http://other.aether.local/").is_none());
        assert!(launch_exchange(&local_service, "https://prometheus.aether.local/").is_none());
    }
}
