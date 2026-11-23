use super::apache_htpasswd::provision_apache_htpasswd_if_configured;
use super::lock::is_pid_alive;
use super::state::ProvisionStateStore;
use super::steps::build_allowed_hosts_and_cors_for_bind;
use super::ProvisionPaths;
use std::fs;
use std::net::IpAddr;

#[test]
fn is_pid_alive_rejects_zero_and_out_of_range_u32_pids() {
    assert!(!is_pid_alive(0));
    assert!(!is_pid_alive(u32::MAX));
    assert!(!is_pid_alive((i32::MAX as u32).saturating_add(1)));
    assert!(is_pid_alive(std::process::id()));
}

#[test]
fn apache_htpasswd_does_not_write_random_password_when_master_creds_encrypted() {
    let tmp = std::env::temp_dir().join(format!("af-htpasswd-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp).unwrap();
    let paths = ProvisionPaths::for_root(tmp.clone()).unwrap();
    fs::create_dir_all(&paths.var_lib_aetherflow).unwrap();
    fs::create_dir_all(tmp.join("etc/apache2/AetherFlow")).unwrap();
    fs::write(
        paths.var_lib_aetherflow.join(".master.creds"),
        r#"{"username":"admin","password":"enc:v1:opaque-ciphertext"}"#,
    )
    .unwrap();

    let prev_pw = std::env::var_os("AETHERFLOW_PASSWORD");
    let prev_secret = std::env::var_os("AETHERFLOW_MASTER_CREDS_SECRET");
    std::env::remove_var("AETHERFLOW_PASSWORD");
    std::env::remove_var("AETHERFLOW_MASTER_CREDS_SECRET");

    let store = ProvisionStateStore::new(paths.clone());
    let htpasswd = tmp.join("etc/apache2/AetherFlow/htpasswd");

    // No plaintext password and no existing file -> returns Ok(None) without creating htpasswd.
    let res = provision_apache_htpasswd_if_configured(&store).unwrap();
    assert_eq!(res, None);
    assert!(!htpasswd.exists());

    // Existing file with valid $2b$ bcrypt hash -> preserved verbatim and returns Ok(Some(path)).
    let valid_entry = format!("operator:{}\n", bcrypt::hash("existing-secret", 4).unwrap());
    fs::write(&htpasswd, &valid_entry).unwrap();
    let res = provision_apache_htpasswd_if_configured(&store).unwrap();
    assert_eq!(res, Some(htpasswd.clone()));
    assert_eq!(fs::read_to_string(&htpasswd).unwrap(), valid_entry);

    // Existing file with corrupt/non-bcrypt line -> returns Ok(None) without overwriting.
    fs::write(&htpasswd, "operator:not-a-bcrypt-hash\n").unwrap();
    let res = provision_apache_htpasswd_if_configured(&store).unwrap();
    assert_eq!(res, None);
    assert_eq!(
        fs::read_to_string(&htpasswd).unwrap(),
        "operator:not-a-bcrypt-hash\n"
    );

    if let Some(v) = prev_pw {
        std::env::set_var("AETHERFLOW_PASSWORD", v);
    }
    if let Some(v) = prev_secret {
        std::env::set_var("AETHERFLOW_MASTER_CREDS_SECRET", v);
    }
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn build_allowed_hosts_seeds_non_loopback_bind_and_discovered_lan_ip() {
    let lan_ip: IpAddr = "192.168.10.25".parse().unwrap();
    let (hosts, cors) = build_allowed_hosts_and_cors_for_bind("0.0.0.0", "8080", None, Some(lan_ip));
    assert_eq!(hosts, "localhost,127.0.0.1,192.168.10.25");
    assert_eq!(
        cors,
        "http://localhost:8080,http://127.0.0.1:8080,http://192.168.10.25:8080"
    );

    let (hosts_explicit, _) =
        build_allowed_hosts_and_cors_for_bind("10.0.0.5", "8080", None, Some(lan_ip));
    assert_eq!(hosts_explicit, "localhost,127.0.0.1,10.0.0.5");

    let (hosts_loopback, _) =
        build_allowed_hosts_and_cors_for_bind("127.0.0.1", "8080", None, Some(lan_ip));
    assert_eq!(hosts_loopback, "localhost,127.0.0.1");
}
