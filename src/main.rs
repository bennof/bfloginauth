// Copyright (c) 2026 Benjamin Benno Falkner
// SPDX-License-Identifier: MIT

mod cli;
mod config;
mod html;
mod keys;
mod server;
mod store;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// Small OAuth2 login server (authorization code + PKCE) for nginx.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Path to the config file.
    /// [default: ./bfloginauth.toml if it exists, else /etc/bfloginauth/bfloginauth.toml]
    #[arg(short, long, global = true, env = "BFLOGINAUTH_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the server (default when no command is given).
    Serve,
    /// Create an example config.
    Init,
    /// Print an Argon2id hash for a password.
    HashPassword {
        /// Read the password from stdin instead of prompting.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Manage users.
    #[command(subcommand)]
    User(UserCmd),
    /// Manage allowed redirect URLs.
    #[command(subcommand)]
    Redirect(RedirectCmd),
}

#[derive(Subcommand)]
enum UserCmd {
    /// Add a user (prompts for the password).
    Add {
        name: String,
        /// Role(s); repeat the flag or separate with commas.
        #[arg(short, long = "role")]
        roles: Vec<String>,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Remove a user.
    #[command(alias = "rm")]
    Remove { name: String },
    /// List users.
    #[command(alias = "ls")]
    List,
    /// Change a user's password.
    Passwd {
        name: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Show or change roles.
    Roles {
        name: String,
        /// Replace all roles.
        #[arg(long, value_delimiter = ',', num_args = 0..)]
        set: Option<Vec<String>>,
        /// Add role(s).
        #[arg(long)]
        add: Vec<String>,
        /// Remove role(s).
        #[arg(long)]
        remove: Vec<String>,
    },
    /// Disable a user (login and /verify fail).
    Disable { name: String },
    /// Re-enable a user.
    Enable { name: String },
}

#[derive(Subcommand)]
enum RedirectCmd {
    /// Allow a URL (must match the redirect_uri exactly).
    Add { url: String },
    /// Remove a URL.
    #[command(alias = "rm")]
    Remove { url: String },
    /// List allowed URLs.
    #[command(alias = "ls")]
    List,
}

const LOCAL_CONFIG: &str = "bfloginauth.toml";
const SYSTEM_CONFIG: &str = "/etc/bfloginauth/bfloginauth.toml";

/// `init` without a path always writes to the current directory, never to /etc.
fn config_path(given: Option<PathBuf>, cmd: &Cmd) -> PathBuf {
    if let Some(p) = given {
        return p;
    }
    let local = PathBuf::from(LOCAL_CONFIG);
    if matches!(cmd, Cmd::Init) || local.exists() {
        local
    } else {
        PathBuf::from(SYSTEM_CONFIG)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let cmd = args.cmd.unwrap_or(Cmd::Serve);
    let config = config_path(args.config, &cmd);
    let path = config.as_path();
    match cmd {
        Cmd::Serve => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();
            server::run(config).await
        }
        Cmd::Init => cli::init(path),
        Cmd::HashPassword { password_stdin } => {
            println!(
                "{}",
                cli::hash_password(&cli::read_password(password_stdin)?)?
            );
            Ok(())
        }
        Cmd::User(c) => match c {
            UserCmd::Add {
                name,
                roles,
                password_stdin,
            } => cli::user_add(path, &name, &roles, password_stdin),
            UserCmd::Remove { name } => cli::user_remove(path, &name),
            UserCmd::List => cli::user_list(path),
            UserCmd::Passwd {
                name,
                password_stdin,
            } => cli::user_passwd(path, &name, password_stdin),
            UserCmd::Roles {
                name,
                set,
                add,
                remove,
            } => cli::user_roles(path, &name, set.as_deref(), &add, &remove),
            UserCmd::Disable { name } => cli::user_set_disabled(path, &name, true),
            UserCmd::Enable { name } => cli::user_set_disabled(path, &name, false),
        },
        Cmd::Redirect(c) => match c {
            RedirectCmd::Add { url } => cli::redirect_add(path, &url),
            RedirectCmd::Remove { url } => cli::redirect_remove(path, &url),
            RedirectCmd::List => cli::redirect_list(path),
        },
    }
}
