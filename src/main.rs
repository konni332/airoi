mod cli;

use clap::Parser;
use crate::cli::execute::execute_cli_command;
use crate::cli::parser::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    execute_cli_command(&cli).await
}


