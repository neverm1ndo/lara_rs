use clap::{Parser, Subcommand};

/// Lara game-server control plane and administration CLI.
#[derive(Debug, Parser)]
#[command(
    name = "lara",
    version,
    about,
    long_about = None,
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Command {
    /// Run the HTTP and realtime control-plane daemon.
    Serve,
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, error::ErrorKind};

    use super::*;

    #[test]
    fn requires_an_explicit_subcommand() {
        let error = Cli::try_parse_from(["lara"]).unwrap_err();

        assert_eq!(
            error.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
        assert!(error.to_string().contains("Usage: lara <COMMAND>"));
    }

    #[test]
    fn parses_serve_for_the_canonical_name_and_compatibility_alias() {
        for program in ["lara", "lara-rs"] {
            let cli = Cli::try_parse_from([program, "serve"]).unwrap();
            assert_eq!(cli.command, Command::Serve);
        }
    }

    #[test]
    fn publishes_package_version_and_only_implemented_commands() {
        let command = Cli::command();

        assert_eq!(command.get_name(), "lara");
        assert_eq!(command.get_version(), Some(env!("CARGO_PKG_VERSION")));
        assert_eq!(
            command
                .get_subcommands()
                .map(clap::Command::get_name)
                .collect::<Vec<_>>(),
            ["serve"]
        );
    }
}
