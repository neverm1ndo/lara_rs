use std::io;

use clap::CommandFactory;
use clap_complete::{Shell, generate};

use crate::cli::{Cli, CompletionShell, CompletionsArgs};

pub fn execute(args: CompletionsArgs) {
    generate(
        shell(args.shell),
        &mut Cli::command(),
        "lara",
        &mut io::stdout(),
    );
}

const fn shell(shell: CompletionShell) -> Shell {
    match shell {
        CompletionShell::Bash => Shell::Bash,
        CompletionShell::Elvish => Shell::Elvish,
        CompletionShell::Fish => Shell::Fish,
        CompletionShell::PowerShell => Shell::PowerShell,
        CompletionShell::Zsh => Shell::Zsh,
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;
    use clap_complete::generate;

    use super::*;

    #[test]
    fn every_supported_shell_generates_the_canonical_binary_name() {
        for completion_shell in [
            CompletionShell::Bash,
            CompletionShell::Elvish,
            CompletionShell::Fish,
            CompletionShell::PowerShell,
            CompletionShell::Zsh,
        ] {
            let mut output = Vec::new();
            generate(
                shell(completion_shell),
                &mut Cli::command(),
                "lara",
                &mut output,
            );
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains("lara"), "{completion_shell:?}");
            assert!(output.contains("doctor"), "{completion_shell:?}");
            assert!(output.contains("render-systemd"), "{completion_shell:?}");
        }
    }
}
