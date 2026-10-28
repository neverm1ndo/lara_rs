use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

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
    /// Inspect and safely edit the configured game-server registry.
    Instance {
        #[command(subcommand)]
        command: InstanceCommand,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum InstanceCommand {
    /// List the effective registry after applying daemon validation rules.
    List(InstanceListArgs),
    /// Register a systemd-managed auxiliary instance.
    Add(InstanceAddArgs),
    /// Edit mutable metadata of an auxiliary instance.
    Edit(InstanceEditArgs),
    /// Remove an auxiliary registration without deleting server files.
    Remove(InstanceRemoveArgs),
    /// Render the validated systemd drop-in for an auxiliary instance.
    RenderSystemd(InstanceRenderSystemdArgs),
}

#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct InstanceConfigArgs {
    /// Explicit production TOML overlay to read or update.
    #[arg(long, default_value = "/etc/lara/production.toml")]
    pub overlay_file: PathBuf,
    /// Environment file used for the same validation as daemon startup.
    #[arg(long, default_value = "/etc/lara/lara.env")]
    pub environment_file: PathBuf,
    /// Output format for automation or human operators.
    #[arg(long, value_enum, default_value_t)]
    pub output: OutputFormat,
}

#[derive(Debug, Args, PartialEq, Eq)]
pub struct InstanceListArgs {
    #[command(flatten)]
    pub config: InstanceConfigArgs,
}

#[derive(Debug, Args, PartialEq, Eq)]
pub struct InstanceAddArgs {
    /// Stable lowercase instance identifier used by APIs and systemd.
    pub id: String,
    /// Human-readable name shown in the control panel.
    #[arg(long)]
    pub display_name: String,
    /// Runtime environment classification.
    #[arg(long, value_enum, default_value_t)]
    pub environment: InstanceEnvironmentArg,
    /// Isolated root containing only this game server's resources.
    #[arg(long)]
    pub storage_root: PathBuf,
    /// Enabled panel capabilities. May be repeated.
    #[arg(long = "capability", value_enum, default_values_t = [
        InstanceCapabilityArg::Overview,
        InstanceCapabilityArg::Lifecycle,
        InstanceCapabilityArg::Incidents,
    ])]
    pub capabilities: Vec<InstanceCapabilityArg>,
    /// Stable navigation order in the client manifest.
    #[arg(long, default_value_t = 100)]
    pub sort_order: u32,
    /// Override the default `lara-game@<id>.service` unit name.
    #[arg(long)]
    pub systemd_unit: Option<String>,
    /// Show the validated mutation without changing the overlay.
    #[arg(long)]
    pub dry_run: bool,
    #[command(flatten)]
    pub config: InstanceConfigArgs,
}

#[derive(Debug, Args, PartialEq, Eq)]
pub struct InstanceEditArgs {
    /// Stable identifier of an existing auxiliary instance.
    pub id: String,
    #[arg(long)]
    pub display_name: Option<String>,
    #[arg(long, value_enum)]
    pub environment: Option<InstanceEnvironmentArg>,
    #[arg(long)]
    pub storage_root: Option<PathBuf>,
    /// Replace the complete capability set. May be repeated.
    #[arg(long = "capability", value_enum)]
    pub capabilities: Vec<InstanceCapabilityArg>,
    #[arg(long)]
    pub sort_order: Option<u32>,
    #[arg(long)]
    pub systemd_unit: Option<String>,
    #[arg(long)]
    pub dry_run: bool,
    #[command(flatten)]
    pub config: InstanceConfigArgs,
}

#[derive(Debug, Args, PartialEq, Eq)]
pub struct InstanceRemoveArgs {
    /// Stable identifier of an existing auxiliary instance.
    pub id: String,
    /// Confirm removal of the registry entry. Server files remain untouched.
    #[arg(long)]
    pub yes: bool,
    /// Show the validated mutation without changing the overlay.
    #[arg(long)]
    pub dry_run: bool,
    #[command(flatten)]
    pub config: InstanceConfigArgs,
}

#[derive(Debug, Args, PartialEq, Eq)]
pub struct InstanceRenderSystemdArgs {
    /// Stable identifier of a registered systemd-managed auxiliary instance.
    pub id: String,
    /// Absolute game-server executable; defaults to <storage-root>/omp-server.
    #[arg(long)]
    pub executable: Option<PathBuf>,
    /// Unix account used by the game-server process.
    #[arg(long, default_value = "lara-game")]
    pub user: String,
    /// Unix group used by the game-server process.
    #[arg(long, default_value = "lara-game")]
    pub group: String,
    /// Root containing host systemd units and instance drop-ins.
    #[arg(long, default_value = "/etc/systemd/system")]
    pub systemd_directory: PathBuf,
    /// Directory for optional per-instance process environment files.
    #[arg(long, default_value = "/etc/lara/game-instances")]
    pub instance_environment_directory: PathBuf,
    /// Show paths and generated content without changing the host.
    #[arg(long)]
    pub dry_run: bool,
    /// Permit replacement of an existing non-identical drop-in after backup.
    #[arg(long)]
    pub yes: bool,
    /// Write files without asking systemd to reload its unit definitions.
    #[arg(long = "no-reload", action = ArgAction::SetFalse, default_value_t = true)]
    pub reload: bool,
    #[command(flatten)]
    pub config: InstanceConfigArgs,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
pub enum InstanceEnvironmentArg {
    Production,
    Development,
    #[default]
    Testing,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum InstanceCapabilityArg {
    Overview,
    Lifecycle,
    Configuration,
    Incidents,
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
            ["serve", "config", "instance"]
        );
    }

    #[test]
    fn parses_instance_add_with_optional_configuration_capability() {
        let cli = Cli::try_parse_from([
            "lara",
            "instance",
            "add",
            "test",
            "--display-name",
            "Test server",
            "--storage-root",
            "/home/svr_test",
            "--capability",
            "lifecycle",
            "--capability",
            "configuration",
            "--dry-run",
        ])
        .unwrap();

        let Command::Instance {
            command: InstanceCommand::Add(args),
        } = cli.command
        else {
            panic!("expected instance add command")
        };
        assert_eq!(args.id, "test");
        assert_eq!(args.storage_root, PathBuf::from("/home/svr_test"));
        assert_eq!(
            args.capabilities,
            [
                InstanceCapabilityArg::Lifecycle,
                InstanceCapabilityArg::Configuration
            ]
        );
        assert!(args.dry_run);
    }

    #[test]
    fn parses_systemd_render_without_implicit_lifecycle_action() {
        let cli = Cli::try_parse_from([
            "lara",
            "instance",
            "render-systemd",
            "test",
            "--executable",
            "/home/svr_test/omp-server",
            "--dry-run",
            "--no-reload",
        ])
        .unwrap();

        let Command::Instance {
            command: InstanceCommand::RenderSystemd(args),
        } = cli.command
        else {
            panic!("expected instance render-systemd command")
        };
        assert_eq!(args.id, "test");
        assert!(args.dry_run);
        assert!(!args.reload);
        assert!(!args.yes);
    }
}
