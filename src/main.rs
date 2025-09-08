mod cli;

use clap::Parser;
use airoi_core::*;
use crate::cli::execute::execute_cli_command;
use crate::cli::parser::Cli;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    execute_cli_command(&cli)
}


