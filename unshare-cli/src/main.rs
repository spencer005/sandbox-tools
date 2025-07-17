use anyhow::Result;
use std::{env, process};
use unshare_cli::runner;

fn main() {
    let args: Vec<String> = env::args().collect();
    let exit_code = match run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("rwrap: {e:#}");
            1
        }
    };
    process::exit(exit_code);
}

fn run(args: Vec<String>) -> Result<i32> {
    runner::run_clap(args)
}
