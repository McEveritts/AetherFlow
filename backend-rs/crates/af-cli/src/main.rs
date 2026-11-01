//! Binary entrypoint (`af`) for the AetherFlow Unified Rust Administrative CLI (`af-cli`).

use af_cli::{parse_cli_args, execute_invocation, UnixSocketRunnerClient};
use std::process::ExitCode;

fn main() -> ExitCode {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let json_flag_present = raw_args.iter().any(|a| a == "--json");

    match parse_cli_args(&raw_args) {
        Ok(invocation) => {
            let client = UnixSocketRunnerClient::new(&invocation.global.socket_path);
            let envelope = execute_invocation(&invocation, &client);
            let output = envelope.render(invocation.global.json);
            if envelope.status == "ok" {
                println!("{}", output);
                ExitCode::SUCCESS
            } else {
                eprintln!("{}", output);
                ExitCode::from((envelope.exit_code.clamp(1, 255)) as u8)
            }
        }
        Err(err) => {
            let envelope = err.to_error_envelope("cli", "parse");
            let output = envelope.render(json_flag_present);
            eprintln!("{}", output);
            ExitCode::from((envelope.exit_code.clamp(1, 255)) as u8)
        }
    }
}
