use super::super::*;

#[test]
fn test_strict_hex_commit_and_tokens() {
    // 8-digit decimal date must NOT be treated as hex commit
    assert!(!is_hex_commit("20261108"));
    assert!(!is_hex_commit("1234567"));
    assert!(!is_hex_commit("123456")); // too short

    // Valid short hex with letters
    assert!(is_hex_commit("202611a"));
    assert!(is_hex_commit("abcdef0"));
    assert!(is_hex_commit("0123456789abcdef"));

    // 40-char commit
    assert!(is_hex_commit("0000000000000000000000000000000000000000"));
    assert!(is_hex_commit("4b825dc642cb6eb9a060e54bf8d69288fbee4904"));

    // is_valid_target_version_token
    assert!(!is_valid_target_version_token(""));
    assert!(!is_valid_target_version_token("   "));
    assert!(!is_valid_target_version_token("latest"));
    assert!(!is_valid_target_version_token("LATEST"));
    assert!(!is_valid_target_version_token("unknown"));
    assert!(!is_valid_target_version_token("none"));
    assert!(!is_valid_target_version_token("null"));
    assert!(!is_valid_target_version_token("v1.0 with space"));

    assert!(is_valid_target_version_token("v1.2.3"));
    assert!(is_valid_target_version_token("1.2.3"));
    assert!(is_valid_target_version_token("release-1.0.0"));
    assert!(is_valid_target_version_token("1234567")); // 7-digit short hex
    assert!(is_valid_target_version_token(
        "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    ));
    assert!(is_valid_target_version_token(
        "frontend:4b825dc,backend:012345a,proxy:abcdef1"
    ));
}

#[test]
fn test_parse_manifest_and_version_match() {
    // Duplicate keys rejected
    assert!(parse_component_manifest("frontend:4b825dc,frontend:012345a").is_none());
    // Fewer than 2 components rejected
    assert!(parse_component_manifest("frontend:4b825dc").is_none());
    // Frontend/backend/proxy requires all 3
    assert!(parse_component_manifest("frontend:4b825dc,backend:012345a").is_none());
    assert!(parse_component_manifest("backend:012345a,proxy:abcdef1").is_none());
    // All 3 with hex commits valid (including all-digit short SHAs)
    let m = parse_component_manifest("frontend:4b825dc,backend:012345a,proxy:abcdef1");
    assert!(m.is_some());
    assert!(parse_component_manifest("frontend:20261108,backend:012345a,proxy:abcdef1").is_some());
    // All 3 but non-hex commit rejected
    assert!(parse_component_manifest("frontend:nothex12,backend:012345a,proxy:abcdef1").is_none());

    // versions_match_target with manifests
    let exp = "frontend:4b825dc642cb,backend:012345abcdef,proxy:abcdef123456";
    let ach = "frontend:4b825dc,backend:012345a,proxy:abcdef1";
    assert!(versions_match_target(ach, exp));

    // Different length manifest must fail
    let ach_extra = "frontend:4b825dc,backend:012345a,proxy:abcdef1,extra:v1.0";
    assert!(!versions_match_target(ach_extra, exp));
}

#[test]
fn test_case_insensitive_and_all_digit_git_shas() {
    // 1. Case-insensitive SHA prefix matching
    let full_lower = "abcdef1234567890abcdef1234567890abcdef12";
    let short_upper = "ABCDEF12";
    assert!(single_version_matches(short_upper, full_lower));
    assert!(single_version_matches(full_lower, short_upper));
    assert!(versions_match_target(short_upper, full_lower));
    assert!(versions_match_target(full_lower, short_upper));

    // 2. All-digit short Git SHA matching 40-char SHA
    let all_digit_short = "1234567";
    let full_with_hex = "1234567abcdef0123456789abcdef0123456789a"; // 40 chars
    assert_eq!(full_with_hex.len(), 40);
    assert!(single_version_matches(all_digit_short, full_with_hex));
    assert!(single_version_matches(full_with_hex, all_digit_short));
    assert!(versions_match_target(all_digit_short, full_with_hex));

    // Inside frontend,backend,proxy Git manifest, even two all-digit short SHAs match
    let exp_git_manifest = "frontend:1234567890,backend:0123456789,proxy:9876543210";
    let ach_git_manifest = "frontend:1234567,backend:0123456,proxy:9876543";
    assert!(versions_match_target(ach_git_manifest, exp_git_manifest));

    // But 8/9 digit decimal release dates without 40-char context do NOT prefix-match
    assert!(!single_version_matches("20261108", "202611080"));
    assert!(!versions_match_target("20261108", "202611080"));

    // 3. Generic component manifests comp1:1.1,comp2:2.0 vs comp1:1.10,comp2:2.0 do NOT match
    let gen1 = "comp1:1.1,comp2:2.0";
    let gen2 = "comp1:1.10,comp2:2.0";
    assert!(!versions_match_target(gen1, gen2));
    assert!(!versions_match_target(gen2, gen1));

    let gen_same = "comp1:1.1,comp2:2.0";
    assert!(versions_match_target(gen1, gen_same));
}
#[test]
fn test_normalize_version_and_semver_build_metadata() {
    assert_eq!(normalize_version("v1.2.3"), "1.2.3");
    assert_eq!(normalize_version("V1.2.3"), "1.2.3");
    assert_eq!(normalize_version("release-1.2.3"), "1.2.3");
    assert_eq!(normalize_version("release_1.2.3"), "1.2.3");
    assert_eq!(normalize_version("release/1.2.3"), "1.2.3");
    assert_eq!(normalize_version("rel-1.2.3"), "1.2.3");
    assert_eq!(normalize_version("rel_1.2.3"), "1.2.3");
    assert_eq!(normalize_version("release-v1.2.3"), "1.2.3");
    assert_eq!(normalize_version("rel_v1.2.3"), "1.2.3");

    // Build metadata identity preserved across normalization (+debug, +git1, +b1, +20260101, etc.)
    assert_eq!(normalize_version("1.0.0+build.2"), "1.0.0+build.2");
    assert_eq!(normalize_version("1.0.0+debug"), "1.0.0+debug");
    assert_eq!(normalize_version("1.0.0+beta"), "1.0.0+beta");
    assert_eq!(normalize_version("1.0.0+upstream"), "1.0.0+upstream");
    assert_eq!(normalize_version("v1.0.0+20241108"), "1.0.0+20241108");
    assert_eq!(
        normalize_version("1.0.0-rc.1+build.42"),
        "1.0.0-rc.1+build.42"
    );

    // Stacked prefixes stripped
    assert_eq!(normalize_version("release-v1.2.3"), "1.2.3");
    assert_eq!(normalize_version("release_v1.2.3"), "1.2.3");
    assert_eq!(normalize_version("rel-v1.2.3"), "1.2.3");
    assert_eq!(normalize_version("rel_v1.2.3"), "1.2.3");
    assert_eq!(normalize_version("release/v1.2.3"), "1.2.3");

    // Debian + revisions preserved
    assert_eq!(normalize_version("1.2.3+deb11u1"), "1.2.3+deb11u1");
    assert_eq!(normalize_version("1.2.3+deb12u2"), "1.2.3+deb12u2");
    assert_eq!(normalize_version("1.0.0+dfsg"), "1.0.0+dfsg");
    assert_eq!(normalize_version("1.0.0+dfsg1"), "1.0.0+dfsg1");
    assert_eq!(normalize_version("1.0.0+dfsg.1"), "1.0.0+dfsg.1");
    assert_eq!(normalize_version("1.0.0+dfsg-1"), "1.0.0+dfsg-1");
    assert_eq!(normalize_version("1.0.0+ds1"), "1.0.0+ds1");
    assert_eq!(normalize_version("1.0.0+really2.0"), "1.0.0+really2.0");
    assert_eq!(normalize_version("1.0.0+nmu1"), "1.0.0+nmu1");
    assert_eq!(normalize_version("1.0.0+b1"), "1.0.0+b1");
    assert_eq!(normalize_version("1.0.0+b2"), "1.0.0+b2");
    assert_eq!(normalize_version("1.0.0+u2"), "1.0.0+u2");

    // normalize_version_str alias preserves build metadata
    assert_eq!(
        normalize_version_str("release_2.0.0+build.1"),
        "2.0.0+build.1"
    );

    // single_version_matches works with build metadata & release prefixes (SemVer equivalence)
    assert!(single_version_matches("1.0.0+build.2", "1.0.0"));
    assert!(single_version_matches("1.0.0", "1.0.0+build.2"));
    assert!(single_version_matches("1.0.0+debug", "1.0.0"));
    assert!(single_version_matches("release-v1.0.0", "1.0.0"));
    assert!(single_version_matches("release_1.0.0", "v1.0.0"));

    // Target certification distinguishes build metadata (+debug, +build.2, etc.)
    assert!(!versions_match_target("1.0.0", "1.0.0+debug"));
    assert!(!versions_match_target("1.0.0+debug", "1.0.0"));
    assert!(!versions_match_target("1.0.0+build.2", "1.0.0"));
    assert!(versions_match_target("1.0.0+debug", "v1.0.0+debug"));
    assert!(versions_match_target("1.0.0+debug", "release-v1.0.0+debug"));
}

#[test]
fn test_piped_manifest_delimiters_and_component_versions() {
    // Both '=' and ':' delimiters are accepted for 3-component piped manifests
    assert!(matches_component_manifest(
        "frontend=1.0,backend=2.0,proxy=3.0",
        "frontend:1.0,backend:2.0,proxy:3.0"
    ));
    assert!(matches_component_manifest(
        "frontend:1.0,backend:2.0,proxy:3.0",
        "frontend=1.0,backend=2.0,proxy:3.0"
    ));
    assert!(matches_component_manifest(
        "frontend=v1.0,backend=v2.0,proxy=v3.0",
        "frontend=1.0,backend=2.0,proxy:3.0"
    ));
    assert!(versions_match_target(
        "frontend=1.0,backend=2.0,proxy=3.0",
        "frontend:1.0,backend:2.0,proxy:3.0"
    ));
    assert!(versions_match_target(
        "frontend=v1.0,backend=v2.0,proxy=v3.0",
        "frontend:1.0,backend:2.0,proxy:3.0"
    ));
}

#[test]
fn test_source_aware_target_validation_debian_and_manifest() {
    assert!(validate_target_version("1.0~rc1-1"));
    assert!(validate_target_version("1:1.0-1"));
    assert!(validate_target_version("1.0.0+git1"));
    assert!(validate_target_version(
        "frontend=1.0,backend=2.0,proxy=3.0"
    ));
    assert!(validate_target_version(
        "frontend:1.0,backend:2.0,proxy:3.0"
    ));

    // Dangerous characters rejected
    assert!(!validate_target_version("../etc/passwd"));
    assert!(!validate_target_version("1.0.0; rm -rf /"));
    assert!(!validate_target_version("1.0.0 && whoami"));
    assert!(!validate_target_version("latest"));
    assert!(!validate_target_version("unknown"));
    assert!(!validate_target_version(""));
}

#[test]
fn test_case_preservation_for_target_certification() {
    assert!(!versions_match_target("1.0.0+Debug", "1.0.0+debug"));
    assert!(!versions_match_target("1.0.0+debug", "1.0.0+Debug"));
    assert!(versions_match_target("1.0.0+Debug", "v1.0.0+Debug"));
    assert!(versions_match_target("Release-v1.0.0+Debug", "1.0.0+Debug"));
    assert!(versions_match_target("version-v1.0.0+Debug", "1.0.0+Debug"));
    assert!(versions_match_target("ver-1.0.0+Debug", "1.0.0+Debug"));
    assert!(versions_match_target("deadbeef1234", "DEADBEEF1234"));
    assert!(versions_match_target("DEADBEEF1234", "deadbeef1234"));
}

#[test]
fn test_reject_incomplete_or_malformed_component_manifests() {
    assert!(!validate_target_version("frontend=1.0,backend=2.0"));
    assert!(!validate_target_version("frontend:1.0,backend:2.0"));
    assert!(!validate_target_version("frontend=1.0,backend=2.0,proxy="));
    assert!(!validate_target_version(
        "frontend=1.0,backend=2.0,proxy=3.0,extra=4.0"
    ));

    assert!(validate_target_version(
        "frontend=1.0,backend=2.0,proxy=3.0"
    ));
    assert!(validate_target_version(
        "frontend:1.0,backend:2.0,proxy:3.0"
    ));
    assert!(validate_target_version("1:1.0.0~rc1-1+b1"));
}

#[test]
fn test_parse_component_manifest_rejects_empty_and_duplicate_entries() {
    // Empty segments (leading, trailing, double comma, whitespace-padded)
    assert!(parse_component_manifest("frontend=1.0,,backend=2.0,proxy=3.0").is_none());
    assert!(parse_component_manifest("frontend=1.0,backend=2.0,proxy=3.0,").is_none());
    assert!(parse_component_manifest(",frontend=1.0,backend=2.0,proxy=3.0").is_none());
    assert!(parse_component_manifest("frontend=1.0,  ,backend=2.0,proxy=3.0").is_none());
    assert!(!validate_target_version(
        "frontend=1.0,,backend=2.0,proxy=3.0"
    ));
    assert!(!validate_target_version(
        "frontend=1.0,backend=2.0,proxy=3.0,"
    ));
    assert!(!validate_target_version(
        ",frontend=1.0,backend=2.0,proxy=3.0"
    ));
    assert!(!validate_target_version(
        "frontend=1.0,  ,backend=2.0,proxy=3.0"
    ));

    // Duplicate component keys
    assert!(parse_component_manifest("frontend=1.0,frontend=2.0,backend=2.0,proxy=3.0").is_none());
    assert!(parse_component_manifest("frontend:1.0,backend:2.0,proxy:3.0,backend:2.0").is_none());
    assert!(parse_component_manifest("frontend:1.0,backend:2.0,proxy:3.0,proxy:3.0").is_none());
    assert!(!validate_target_version(
        "frontend=1.0,frontend=2.0,backend=2.0,proxy=3.0"
    ));
    assert!(!validate_target_version(
        "frontend:1.0,backend:2.0,proxy:3.0,backend:2.0"
    ));
}

#[test]
fn test_malformed_manifest_never_matches_itself() {
    assert!(!versions_match_target(
        "frontend=1.0,,backend=2.0,proxy=3.0",
        "frontend=1.0,,backend=2.0,proxy=3.0"
    ));
    assert!(!single_version_matches(
        "frontend=1.0,,backend=2.0,proxy=3.0",
        "frontend=1.0,,backend=2.0,proxy=3.0"
    ));
}

#[test]
fn test_target_validator_rejects_credential_tokens_and_preserves_debian_epoch() {
    assert!(!validate_target_version("password:secret"));
    assert!(!validate_target_version("token:abc"));
    assert!(!validate_target_version("user:pass"));
    assert!(validate_target_version("1:1.0.0~rc1-1+b1"));
    assert!(validate_target_version("0:1.0.0"));
    assert!(validate_target_version("1.0.0+build-"));
    assert!(validate_target_version("1.0.0+build--"));
}
#[test]
fn test_invalid_placeholder_and_channel_manifests_rejected() {
    assert!(!validate_target_version(
        "frontend:latest,backend:latest,proxy:latest"
    ));
    assert!(!validate_target_version("comp1:latest,comp2:unknown"));
    assert!(!validate_target_version(
        "frontend=unknown,backend=1.0.0,proxy=1.0.0"
    ));

    assert!(!versions_match_target(
        "frontend:latest,backend:latest,proxy:latest",
        "frontend:latest,backend:latest,proxy:latest"
    ));
    assert!(!versions_match_target(
        "comp1:latest,comp2:unknown",
        "comp1:latest,comp2:unknown"
    ));
    assert!(!versions_match_target(
        "frontend=unknown,backend=1.0.0,proxy=1.0.0",
        "frontend=unknown,backend=1.0.0,proxy=1.0.0"
    ));
    assert!(parse_component_manifest("frontend:latest,backend:latest,proxy:latest").is_none());
    assert!(
        parse_piped_component_manifest("frontend:latest,backend:latest,proxy:latest").is_none()
    );
    assert!(parse_component_manifest("comp1:latest,comp2:unknown").is_none());
}
#[test]
fn test_prerelease_version_for_channel_debian_and_semver() {
    assert!(is_prerelease_version_for_channel("1.2.3-foo-1"));
    assert!(is_prerelease_version_for_channel("1.2.3-1.2"));
    assert!(is_prerelease_version_for_channel("1.2.3-rc1"));
    assert!(is_prerelease_version_for_channel("1.2.3~rc1"));
    assert!(is_prerelease_version_for_channel("1.2.3-beta.1"));
    assert!(is_prerelease_version_for_channel("1.0.0-0.1"));

    assert!(!is_prerelease_version_for_channel("1:1.2.3-1+b1"));
    assert!(!is_prerelease_version_for_channel("2.4.5-1ubuntu1"));
    assert!(!is_prerelease_version_for_channel("1.0.0-1deb12u1"));
    assert!(!is_prerelease_version_for_channel("1.2.3-1"));
    assert!(!is_prerelease_version_for_channel("1.2.3"));
}
#[test]
fn test_source_aware_prerelease_version_rules() {
    // is_valid_apt_debian_revision_suffix
    assert!(is_valid_apt_debian_revision_suffix("0.1"));
    assert!(is_valid_apt_debian_revision_suffix("1.2"));
    assert!(is_valid_apt_debian_revision_suffix("1+b1"));
    assert!(is_valid_apt_debian_revision_suffix("1deb12u1"));
    assert!(is_valid_apt_debian_revision_suffix("2ubuntu1"));
    assert!(is_valid_apt_debian_revision_suffix("1"));
    assert!(!is_valid_apt_debian_revision_suffix("rc1"));
    assert!(!is_valid_apt_debian_revision_suffix("beta.1"));
    assert!(!is_valid_apt_debian_revision_suffix("foo-1"));
    assert!(!is_valid_apt_debian_revision_suffix("0.1~rc1"));

    // APT source
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.0.0-0.1",
        Some("apt")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3-1.2",
        Some("apt")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1:1.2.3-1+b1",
        Some("apt")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3-1",
        Some("apt")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "2.4.5-1ubuntu1",
        Some("apt")
    ));
    assert!(is_prerelease_version_for_channel_with_source(
        "1.2.3-rc1",
        Some("apt")
    ));
    assert!(is_prerelease_version_for_channel_with_source(
        "1.2.3-foo-1",
        Some("apt")
    ));
    assert!(is_prerelease_version_for_channel_with_source(
        "1.2.3~rc1",
        Some("apt")
    ));

    // Git / git_tags source
    assert!(is_prerelease_version_for_channel_with_source(
        "1.2.3-1",
        Some("git_tags")
    ));
    assert!(is_prerelease_version_for_channel_with_source(
        "1.0.0-0.1",
        Some("git_tags")
    ));
    assert!(is_prerelease_version_for_channel_with_source(
        "1.2.3-1.2",
        Some("git_tags")
    ));
    assert!(is_prerelease_version_for_channel_with_source(
        "1.2.3-foo-1",
        Some("git_tags")
    ));
    assert!(is_prerelease_version_for_channel_with_source(
        "1:1.2.3-1+b1",
        Some("git_tags")
    ));
    assert!(is_prerelease_version_for_channel_with_source(
        "2.4.5-1ubuntu1",
        Some("git_tags")
    ));

    // Strict SemVer prerelease rejection for git / github sources including debug and revisions
    for src in ["github", "github_release", "git", "git_tags"] {
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-debug.1",
            Some(src)
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-1",
            Some(src)
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-ubuntu1",
            Some(src)
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3",
            Some(src)
        ));
    }

    // Default / None source
    assert!(is_prerelease_version_for_channel_with_source(
        "1.0.0-0.1",
        None
    ));
    assert!(is_prerelease_version_for_channel_with_source(
        "1.2.3-1.2",
        None
    ));
    assert!(is_prerelease_version_for_channel_with_source(
        "1.2.3-foo-1",
        None
    ));
    assert!(is_prerelease_version_for_channel_with_source(
        "1.2.3-debug.1",
        None
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3-1", None
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1:1.2.3-1+b1",
        None
    ));
}
#[test]
fn test_build_metadata_stable_classification() {
    assert!(!is_prerelease_version_for_channel("v1.2.3+rc.1"));
    assert!(!is_prerelease_version_for_channel_with_source(
        "v1.2.3+rc.1",
        None
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "v1.2.3+rc.1",
        Some("git")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "v1.2.3+rc.1",
        Some("github")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3+dev.1",
        Some("git")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3+debug",
        Some("github")
    ));

    // True prereleases must still be classified as prereleases
    assert!(is_prerelease_version_for_channel("1.2.3-rc.1"));
    assert!(is_prerelease_version_for_channel("1.2.3~rc.1"));
    assert!(is_prerelease_version_for_channel_with_source(
        "1.2.3-rc.1",
        Some("git")
    ));
}
#[test]
fn parse_apt_policy_candidate_handles_revisions_none_and_first_entry() {
    assert_eq!(
        parse_apt_policy_candidate(
            "plexmediaserver:\n  Installed: 1.40.0\n  Candidate: 2:2.53.0+ds-1~deb12u1\n  Version table:\n"
        ),
        Some("2:2.53.0+ds-1~deb12u1")
    );
    assert_eq!(
        parse_apt_policy_candidate("pkg:\n  Installed: (none)\n  Candidate: (none)\n"),
        None
    );
    assert_eq!(parse_apt_policy_candidate("pkg:\n  Candidate:   \n"), None);
    assert_eq!(parse_apt_policy_candidate("pkg:\n  Installed: 1.0\n"), None);
    assert_eq!(
        parse_apt_policy_candidate("pkg:\n  Candidate: (none)\n  Candidate: 1.2.3\n"),
        None
    );
}
#[test]
fn test_exact_apt_version_validation_and_dpkg_status_parsing() {
    for valid in [
        "1:0.14.0-1+deb12u1",
        "4.0.6+dfsg-3+deb13u1",
        "1.0.20210914-1.1+b1",
        "10.10.3+deb12",
        "0.9.21.1-1~bpo12+1",
        "2.0.3-4",
        "11.0.0",
    ] {
        assert!(
            validate_exact_apt_version(valid),
            "valid Debian version {valid:?} must be accepted"
        );
    }

    for invalid in [
        "",
        "latest",
        "v1.2.3",
        "V1.2.3",
        "1.2.*",
        "1.2.3-",
        "1.2_3",
        "deadbeef",
        "quassel-core=1:0.14.0-1",
        "1:0.14.0-1/bookworm",
        "1::0.14.0-1",
        "epoch:1.0-1",
        "1.0..2",
        "1.0 2",
    ] {
        assert!(
            !validate_exact_apt_version(invalid),
            "invalid APT target {invalid:?} must be rejected"
        );
    }

    assert_eq!(
        parse_installed_dpkg_status_version("installed 4.0.6+dfsg-3+deb13u1\n"),
        Some("4.0.6+dfsg-3+deb13u1")
    );
    assert_eq!(
        parse_installed_dpkg_status_version("installed 1:0.14.0-1+deb12u1\n"),
        Some("1:0.14.0-1+deb12u1")
    );
    for bad_dpkg in [
        "config-files 4.0.6+dfsg-3+deb13u1\n",
        "half-installed 1:0.14.0-1+deb12u1\n",
        "unpacked 1:0.14.0-1+deb12u1\n",
        "not-installed \n",
        "installed 1:0.14.0-1 extra\n",
        "installed v1.2.3\n",
        "",
    ] {
        assert_eq!(
            parse_installed_dpkg_status_version(bad_dpkg),
            None,
            "non-installed or malformed dpkg output {bad_dpkg:?} must fail closed"
        );
    }

    assert!(apt_receipt_matches_live_debian_revision(
        "apt",
        "0.14.0",
        "1:0.14.0-1+deb12u1"
    ));
    assert!(!apt_receipt_matches_live_debian_revision(
        "apt",
        "0.14.1",
        "1:0.14.0-1+deb12u1"
    ));
    assert!(!apt_receipt_matches_live_debian_revision(
        "apt",
        "0.14.0",
        "1:0.14.0~rc1-1"
    ));
}
