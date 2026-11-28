mod mfa;
mod middleware;
mod revocation;
mod sessions;
mod setup_login;
mod tokens;

#[cfg(test)]
mod mfa_tests;
#[cfg(test)]
mod middleware_tests;
#[cfg(test)]
mod session_tests;

#[cfg(test)]
pub(crate) use mfa::match_recovery_in_connection;
pub(crate) use mfa::{
    consume_recovery_code, consume_totp_code, generate_recovery_codes, has_matching_totp_code,
    hash_recovery_codes, store_recovery_codes, validate_recovery_code, verify_user_totp_stepup,
    RecoveryCodeMatch,
};
pub use mfa::{
    disable_2fa, mfa_login_verify, setup_2fa, verify_2fa, CodeRequest, Disable2FaRequest,
    MfaVerifyRequest,
};

pub use middleware::{admin_only_middleware, auth_middleware, csrf_middleware, issue_csrf_token};
pub(crate) use middleware::{is_production_or_release_env, require_admin};

#[allow(unused_imports)]
pub(crate) use revocation::{
    evict_rotation_grace_for_family, evict_rotation_grace_for_user,
    is_session_token_revoked_beyond_grace, is_session_token_revoked_beyond_grace_for_fp,
    is_session_token_revoked_beyond_grace_with_conn, resolve_current_session_jti,
};
pub(crate) use revocation::{
    finalize_user_credential_revocation, oidc_session_tag, resolve_session_family_id,
    revoke_all_user_credentials_in_tx,
};
pub use revocation::{spawn_rotation_state_sweeper, sweep_expired_rotation_state};

#[cfg(test)]
pub use sessions::refresh_session;
pub use sessions::{
    list_active_sessions, logout, refresh_session_with_peer, revoke_session, verify_proxy_auth,
};

pub(crate) use setup_login::password_too_long;
pub use setup_login::{
    check_setup_needed, ensure_setup_bootstrap_token, get_session, local_login,
    save_master_credentials, setup_admin, verify_password, CredentialsRequest,
};

#[cfg(test)]
pub(crate) use tokens::mint_plugin_jwt;
#[allow(unused_imports)]
pub(crate) use tokens::query_user_credential_version;
pub use tokens::{
    api_error, client_fingerprint, create_standard_jwt, decode_session_claims, jwt_secret_bytes,
    legacy_client_fingerprint, matches_client_fingerprint, resolve_raw_token,
    secure_cookie_enabled, validate_startup_jwt_secret, AuthUser, PeerPrincipal, SessionAuthTime,
    SessionClaims,
};
pub(crate) use tokens::{
    blocking_auth_work, blocking_response, column_exists, create_session_jwt_in_conn,
    load_active_human_subject, load_active_peer_subject, load_active_subject_for_request,
    set_session_cookie, table_exists, verify_active_session_on_conn, ActiveSubject, RotationGrace,
    SessionValidationError, SubjectStatusError,
};
