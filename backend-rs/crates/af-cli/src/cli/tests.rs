use super::parse::parse_help_topic;
use super::*;

#[test]
fn test_parse_hosts_subcommand() {
    let update_args = vec![
        "update".to_string(),
        "10.0.0.1".to_string(),
        "app.aether.local".to_string(),
    ];
    let cmd = parse_hosts_subcommand(&update_args).unwrap();
    assert_eq!(
        cmd,
        HostsCliCommand::Update {
            ip: "10.0.0.1".to_string(),
            domains: vec!["app.aether.local".to_string()],
        }
    );

    let remove_args = vec!["remove".to_string(), "app.aether.local".to_string()];
    let cmd = parse_hosts_subcommand(&remove_args).unwrap();
    assert_eq!(
        cmd,
        HostsCliCommand::Remove {
            domains: vec!["app.aether.local".to_string()],
        }
    );

    let reconcile_args = vec![
        "reconcile".to_string(),
        "127.0.0.1".to_string(),
        "app1.aether.local".to_string(),
    ];
    let cmd = parse_hosts_subcommand(&reconcile_args).unwrap();
    assert_eq!(
        cmd,
        HostsCliCommand::Reconcile {
            ip: "127.0.0.1".to_string(),
            domains: vec!["app1.aether.local".to_string()],
        }
    );

    let reconcile_empty = vec!["reconcile".to_string()];
    let cmd = parse_hosts_subcommand(&reconcile_empty).unwrap();
    assert_eq!(
        cmd,
        HostsCliCommand::Reconcile {
            ip: "127.0.0.1".to_string(),
            domains: Vec::new(),
        }
    );

    assert_eq!(parse_help_topic("hosts"), HelpTopic::Hosts);
    assert_eq!(parse_help_topic("dns"), HelpTopic::Hosts);
    assert!(render_help_text(HelpTopic::Hosts).contains("af hosts <update|remove|reconcile>"));
}
