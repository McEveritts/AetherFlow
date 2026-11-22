use super::*;
use serde_json::Value;
use std::cell::RefCell;
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};

fn output(status: i32, stdout: &str) -> std::io::Result<Output> {
    Ok(Output {
        status: ExitStatus::from_raw(status << 8),
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
    })
}

#[test]
fn port_mutation_preserves_service_settings_and_reloads_before_restarting() {
    let root = std::env::temp_dir().join(format!("af-unit-port-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let mut changed = Vec::new();
    for app in ["overseerr", "jellyseerr", "listenarr"] {
        let name = format!("{app}.service");
        let spec = native_app_spec(app, "");
        assert!(spec.config_paths.iter().any(|path| path.ends_with(&name)));
        let path = root.join(name);
        let (directive, updated) = if app == "listenarr" {
            (
                "Environment=ASPNETCORE_URLS=http://127.0.0.1:5055",
                "Environment=ASPNETCORE_URLS=http://127.0.0.1:18990",
            )
        } else {
            ("Environment=\"PORT=5055\"", "Environment=\"PORT=18990\"")
        };
        let unit = format!("[Unit]\nDescription=Fixture\n[Service]\nEnvironment=CONFIG_DIRECTORY=/var/lib/{app}\n{directive}\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n");
        fs::write(&path, &unit).unwrap();
        let mutate = if app == "listenarr" {
            mutate_systemd_aspnetcore_urls
        } else {
            mutate_systemd_port
        };
        assert!(mutate(&path, 18990).unwrap());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            unit.replace(directive, updated)
        );
        assert!(!mutate(&path, 18990).unwrap());
        changed.push(path.to_string_lossy().into_owned());
    }
    let mut commands = Vec::new();
    reload_changed_units(&changed, |args| {
        commands.push(args.join(" "));
        output(0, "")
    })
    .unwrap();
    assert_eq!(
        commands,
        [
            "daemon-reload",
            "try-restart -- overseerr.service",
            "try-restart -- jellyseerr.service",
            "try-restart -- listenarr.service",
        ]
    );
    assert!(!service_units_changed(&[
        "settings.json".into(),
        "foo.service.bak".into()
    ]));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn transmission_stops_before_mutation_and_recovers_after_a_write_error() {
    for (state, stop, fail_write) in [
        ("active", 0, false),
        ("active", 0, true),
        ("active", 1, false),
        ("inactive", 0, false),
    ] {
        let commands = RefCell::new(Vec::new());
        let result = with_transmission_stopped(
            true,
            |args| {
                commands.borrow_mut().push(args[0].to_owned());
                match args[0] {
                    "show" => output(0, state),
                    "stop" => output(stop, ""),
                    "start" => output(0, ""),
                    cmd => panic!("unexpected command {cmd}"),
                }
            },
            || {
                commands.borrow_mut().push("write".into());
                anyhow::ensure!(!fail_write, "fixture write error");
                Ok(())
            },
        );
        assert_eq!(result.is_err(), stop != 0 || fail_write);
        let expected: &[_] = match (state, stop) {
            ("active", 0) => &["show", "stop", "write", "start"],
            ("active", _) => &["show", "stop"],
            _ => &["show", "write"],
        };
        assert_eq!(*commands.borrow(), expected);
    }
}

#[test]
fn transmission_repairs_an_enabled_empty_host_whitelist() {
    assert!(native_app_spec("transmission", "")
        .config_paths
        .iter()
        .any(|path| path == TRANSMISSION_CONFIG_PATHS[2]));
    let root = std::env::temp_dir().join(format!(
        "af-transmission-whitelist-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&root).unwrap();
    let path = root.join("settings.json");
    fs::write(
        &path,
        r#"{"rpc-host-whitelist-enabled": true, "rpc-host-whitelist": ""}"#,
    )
    .unwrap();
    let ingress = af_models::AppIngressConfig {
        public_domain: "downloads.example.net".into(),
        ..Default::default()
    };
    assert!(mutate_transmission_whitelist(&path, "example.org", Some(&ingress)).unwrap());
    assert!(!mutate_transmission_whitelist(&path, "example.org", Some(&ingress)).unwrap());
    let settings: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(settings["rpc-host-whitelist-enabled"], true);
    assert_eq!(settings["rpc-host-whitelist"],
        "transmission.aether.local,localhost,127.0.0.1,transmission.example.org,downloads.example.net");
    fs::remove_dir_all(root).unwrap();
}
