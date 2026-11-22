use super::lock::is_pid_alive;

#[test]
fn is_pid_alive_rejects_zero_and_out_of_range_u32_pids() {
    assert!(!is_pid_alive(0));
    assert!(!is_pid_alive(u32::MAX));
    assert!(!is_pid_alive((i32::MAX as u32).saturating_add(1)));
    assert!(is_pid_alive(std::process::id()));
}
