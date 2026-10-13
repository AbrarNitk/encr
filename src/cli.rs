use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::keys::Complexity;

#[derive(Debug, Parser)]
#[command(
    name = "encr",
    version,
    about = "Fast, streaming, authenticated encryption for files and directories"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt a file, or a directory (archived and compressed first)
    Encrypt(EncryptArgs),
    /// Decrypt a file produced by `encrypt`, restoring the original file or directory
    Decrypt(DecryptArgs),
    /// Decrypt in memory and list the contents without writing anything to disk
    Show(ShowArgs),
    /// Generate a random 256-bit key
    GenerateKey,
    /// Generate a random password
    GeneratePassword(PasswordArgs),
}

#[derive(Debug, Args)]
pub struct KeyArg {
    /// Key from `generate-key`, or any passphrase. Prompted for when omitted.
    #[arg(
        short,
        long,
        env = "ENCR_KEY",
        hide_env_values = true,
        allow_hyphen_values = true
    )]
    pub key: Option<String>,
}

#[derive(Debug, Args)]
pub struct EncryptArgs {
    /// File or directory to encrypt
    #[arg(short, long)]
    pub input: PathBuf,

    /// Destination of the encrypted file
    #[arg(short, long)]
    pub output: PathBuf,

    #[command(flatten)]
    pub key: KeyArg,

    /// Zstandard level used when archiving a directory
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(i32).range(1..=19))]
    pub compression_level: i32,

    /// Overwrite the output if it already exists
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct DecryptArgs {
    /// Encrypted file
    #[arg(short, long)]
    pub input: PathBuf,

    /// Destination file, or directory for encrypted directories
    #[arg(short, long)]
    pub output: PathBuf,

    #[command(flatten)]
    pub key: KeyArg,

    /// Overwrite an existing file, or extract into an existing directory
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// Encrypted file
    #[arg(short, long)]
    pub input: PathBuf,

    #[command(flatten)]
    pub key: KeyArg,
}

#[derive(Debug, Args)]
pub struct PasswordArgs {
    /// Character classes to draw from
    #[arg(long, value_enum, default_value_t = Level::Strong)]
    pub level: Level,

    /// Number of characters
    #[arg(long, default_value_t = 24, value_parser = clap::value_parser!(u16).range(8..=4096))]
    pub length: u16,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Level {
    /// Lowercase letters and digits
    Weak,
    /// Mixed-case letters and digits
    Medium,
    /// Mixed-case letters, digits and symbols
    Strong,
}

impl From<Level> for Complexity {
    fn from(level: Level) -> Self {
        match level {
            Level::Weak => Self::Weak,
            Level::Medium => Self::Medium,
            Level::Strong => Self::Strong,
        }
    }
}
