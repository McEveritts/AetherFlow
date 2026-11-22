mod authorize;
mod clients;
mod device;
mod google;
mod introspection;
mod keys;
mod token_endpoint;

#[cfg(test)]
mod device_tests;
#[cfg(test)]
mod keys_and_google_tests;
#[cfg(test)]
mod token_tests;

pub use authorize::{oidc_authorize, oidc_consent, AuthorizeQuery, ConsentRequest};
pub use clients::{create_oidc_client, delete_oidc_client, get_oidc_clients};
pub use device::{oidc_device_authorize, oidc_device_consent, oidc_device_verify};
pub use google::{google_callback, google_login};
pub use introspection::{oidc_introspect, oidc_revoke, oidc_userinfo};
pub use keys::{
    get_base_url, get_base_url_for_peer, get_oidc_issuer, get_oidc_issuer_for_peer, oidc_discovery,
    oidc_jwks, OidcKeyMaterial,
};
#[allow(unused_imports)]
pub(crate) use keys::{is_loopback_authority, is_valid_host_authority};
pub use token_endpoint::oidc_token;
