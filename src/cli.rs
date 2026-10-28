use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    /// Initialize and validate Lara configuration files.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum ConfigCommand {
    /// Create a safe production overlay and environment-file template.
    Init(ConfigInitArgs),
    /// Validate configuration exactly as the daemon would load it.
    Validate(ConfigValidateArgs),
    /// Print canonical operational paths without reading secrets.
    Paths(ConfigPathsArgs),
}

#[derive(Debug, Args, PartialEq, Eq)]
pub struct ConfigInitArgs {
    /// Directory containing Lara's host configuration.
    #[arg(long, default_value = "/etc/lara")]
    pub config_dir: PathBuf,
    /// Show the mutation plan without writing any file.
    #[arg(long)]
    pub dry_run: bool,
    /// Explicitly permit replacement of existing files after making backups.
    #[arg(long)]
    pub yes: bool,
    /// Output format for automation or human operators.
    #[arg(long, value_enum, default_value_t)]
    pub output: OutputFormat,
}

#[derive(Debug, Args, PartialEq, Eq)]
pub struct ConfigValidateArgs {
    /// Explicit production TOML overlay.
    #[arg(long, default_value = "/etc/lara/production.toml")]
    pub overlay_file: PathBuf,
    /// Environment file containing secrets and connection strings.
    #[arg(long, default_value = "/etc/lara/lara.env")]
    pub environment_file: PathBuf,
    /// Output format for automation or human operators.
    #[arg(long, value_enum, default_value_t)]
    pub output: OutputFormat,
}

#[derive(Debug, Args, PartialEq, Eq)]
pub struct ConfigPathsArgs {
    /// Directory containing Lara's host configuration.
    #[arg(long, default_value = "/etc/lara")]
    pub config_dir: PathBuf,
    /// Output format for automation or human operators.
    #[arg(long, value_enum, default_value_t)]
    pub output: OutputFormat,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
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
    fn parses_nested_config_commands_and_safe_flags() {
        let cli = Cli::try_parse_from([
            "lara",
            "config",
            "init",
            "--config-dir",
            "/tmp/lara",
            "--dry-run",
            "--output",
            "json",
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            Command::Config {
                command: ConfigCommand::Init(ConfigInitArgs {
                    config_dir: PathBuf::from("/tmp/lara"),
                    dry_run: true,
                    yes: false,
                    output: OutputFormat::Json,
                })
            }
        );
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
            ["serve", "config"]
        );
    }
}
