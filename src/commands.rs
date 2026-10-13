//! Subcommand orchestration: wires paths, keys, archiving and crypto streams together.

use std::{
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::{
    archive::{self, EntryInfo, EntryKind, Stats},
    cli::{Command, DecryptArgs, EncryptArgs, KeyArg, PasswordArgs, ShowArgs},
    crypto::{self, DecryptReader, PayloadKind},
    fs::{self, InputKind, StagedDir, StagedFile},
    keys::{self, Secret},
};

const IO_BUFFER_SIZE: usize = 1 << 20;
const MIN_PASSPHRASE_CHARS: usize = 12;

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Encrypt(args) => encrypt(args),
        Command::Decrypt(args) => decrypt(args),
        Command::Show(args) => show(args),
        Command::GenerateKey => generate_key(),
        Command::GeneratePassword(args) => generate_password(args),
    }
}

fn encrypt(args: EncryptArgs) -> Result<()> {
    let (input, kind) = fs::classify_input(&args.input)?;
    let output = fs::resolve_output(&args.output)?;
    fs::ensure_not_inside(&output, &input)?;
    fs::ensure_absent(&output, args.force)?;
    let secret = read_secret(args.key, true)?;

    let payload = match kind {
        InputKind::File => PayloadKind::File,
        InputKind::Directory => PayloadKind::Archive,
    };
    let sink = BufWriter::with_capacity(IO_BUFFER_SIZE, StagedFile::create(&output)?);
    let mut writer =
        crypto::encryptor(sink, payload, &secret).context("failed to initialise encryption")?;

    let summary = match kind {
        InputKind::File => {
            let file =
                File::open(&input).with_context(|| format!("cannot open `{}`", input.display()))?;
            let bytes = io::copy(
                &mut BufReader::with_capacity(IO_BUFFER_SIZE, file),
                &mut writer,
            )
            .with_context(|| format!("failed to encrypt `{}`", input.display()))?;
            human_size(bytes)
        }
        InputKind::Directory => {
            let stats = archive::pack(&input, &mut writer, args.compression_level)?;
            for path in &stats.skipped {
                eprintln!(
                    "warning: skipped unsupported file type `{}`",
                    path.display()
                );
            }
            describe(&stats)
        }
    };

    let sink = writer
        .finish()
        .context("failed to finalise encrypted output")?;
    let staged = sink
        .into_inner()
        .map_err(io::IntoInnerError::into_error)
        .context("failed to write encrypted output")?;
    staged.commit(args.force)?;

    eprintln!(
        "Encrypted `{}` ({summary}) -> `{}`",
        input.display(),
        output.display()
    );
    Ok(())
}

fn decrypt(args: DecryptArgs) -> Result<()> {
    let input = encrypted_input(&args.input)?;
    let output = fs::resolve_output(&args.output)?;
    fs::ensure_not_inside(&output, &input)?;
    fs::ensure_absent(&output, args.force)?;
    let secret = read_secret(args.key, false)?;
    let (payload, mut reader) = open_encrypted(&input, &secret)?;

    match payload {
        PayloadKind::File => {
            let mut sink = BufWriter::with_capacity(IO_BUFFER_SIZE, StagedFile::create(&output)?);
            let bytes = copy_buffered(&mut reader, &mut sink)
                .with_context(|| format!("failed to decrypt `{}`", input.display()))?;
            reader
                .finish()
                .context("failed to verify the encrypted stream")?;
            let staged = sink
                .into_inner()
                .map_err(io::IntoInnerError::into_error)
                .context("failed to write decrypted output")?;
            staged.commit(args.force)?;
            eprintln!(
                "Decrypted file ({}) -> `{}`",
                human_size(bytes),
                output.display()
            );
        }
        PayloadKind::Archive => {
            if output.is_dir() {
                // Only reachable with --force: merge into the existing directory, like `tar -x`.
                archive::unpack(&mut reader, &output)?;
                reader
                    .finish()
                    .context("failed to verify the encrypted stream")?;
            } else {
                if output.symlink_metadata().is_ok() {
                    bail!("`{}` exists and is not a directory", output.display());
                }
                let staged = StagedDir::create(&output)?;
                archive::unpack(&mut reader, staged.path())?;
                reader
                    .finish()
                    .context("failed to verify the encrypted stream")?;
                staged.commit()?;
            }
            eprintln!("Decrypted directory -> `{}`", output.display());
        }
    }
    Ok(())
}

fn show(args: ShowArgs) -> Result<()> {
    let input = encrypted_input(&args.input)?;
    let secret = read_secret(args.key, false)?;
    let (payload, mut reader) = open_encrypted(&input, &secret)?;
    let mut out = BufWriter::new(io::stdout().lock());

    match payload {
        PayloadKind::File => {
            let bytes = copy_buffered(&mut reader, &mut io::sink()).context("failed to decrypt")?;
            reader
                .finish()
                .context("failed to verify the encrypted stream")?;
            writeln!(
                out,
                "Single file: {} ({bytes} bytes), integrity verified",
                human_size(bytes)
            )?;
        }
        PayloadKind::Archive => {
            writeln!(out, "{:<5} {:>10}  PATH", "TYPE", "SIZE")?;
            let stats = archive::list(&mut reader, |entry| write_entry(&mut out, entry))?;
            reader
                .finish()
                .context("failed to verify the encrypted stream")?;
            writeln!(out, "\n{}, integrity verified", describe(&stats))?;
        }
    }
    out.flush()?;
    Ok(())
}

fn generate_key() -> Result<()> {
    let key = keys::generate_key()?;
    writeln!(io::stdout().lock(), "{}", key.as_str())?;
    Ok(())
}

fn generate_password(args: PasswordArgs) -> Result<()> {
    let password = keys::generate_password(args.level.into(), args.length.into())?;
    writeln!(io::stdout().lock(), "{}", password.as_str())?;
    Ok(())
}

fn encrypted_input(path: &Path) -> Result<PathBuf> {
    let (path, kind) = fs::classify_input(path)?;
    if kind == InputKind::Directory {
        bail!(
            "`{}` is a directory, expected an encrypted file",
            path.display()
        );
    }
    Ok(path)
}

fn open_encrypted(
    path: &Path,
    secret: &Secret,
) -> Result<(PayloadKind, DecryptReader<BufReader<File>>)> {
    let file = File::open(path).with_context(|| format!("cannot open `{}`", path.display()))?;
    // Default-sized buffer: chunk reads are larger than it and bypass it entirely.
    let (header, reader) = crypto::decryptor(BufReader::new(file), secret)
        .with_context(|| format!("cannot decrypt `{}`", path.display()))?;
    Ok((header.payload, reader))
}

fn read_secret(arg: KeyArg, confirm: bool) -> Result<Secret> {
    let value = match arg.key {
        Some(key) => key,
        None => prompt_secret(confirm)?,
    };
    let secret = Secret::new(value)?;
    if confirm && secret.as_raw_key().is_none() && secret.char_count() < MIN_PASSPHRASE_CHARS {
        eprintln!(
            "warning: passphrase is shorter than {MIN_PASSPHRASE_CHARS} characters; \
             consider `encr generate-key` or `encr generate-password`"
        );
    }
    Ok(secret)
}

fn prompt_secret(confirm: bool) -> Result<String> {
    let mut secret = Zeroizing::new(
        rpassword::prompt_password("Key or passphrase: ")
            .context("no key given and no terminal to prompt on (use --key or ENCR_KEY)")?,
    );
    if confirm {
        let again = Zeroizing::new(
            rpassword::prompt_password("Confirm: ").context("failed to read confirmation")?,
        );
        if *secret != *again {
            bail!("the two entries do not match");
        }
    }
    Ok(std::mem::take(&mut *secret))
}

/// Writes straight from the reader's internal buffer, avoiding an intermediate copy.
fn copy_buffered(reader: &mut impl BufRead, writer: &mut impl Write) -> io::Result<u64> {
    let mut total = 0;
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return Ok(total);
        }
        writer.write_all(chunk)?;
        let n = chunk.len();
        reader.consume(n);
        total += n as u64;
    }
}

fn write_entry(out: &mut impl Write, entry: &EntryInfo) -> io::Result<()> {
    let (label, size) = match entry.kind {
        EntryKind::File => ("file", human_size(entry.size)),
        EntryKind::Directory => ("dir", "-".to_owned()),
        EntryKind::Link => ("link", "-".to_owned()),
        EntryKind::Other => ("other", human_size(entry.size)),
    };
    let mut name = entry.path.display().to_string();
    if entry.kind == EntryKind::Directory && !name.ends_with('/') {
        name.push('/');
    }
    if let Some(target) = &entry.link_target {
        name = format!("{name} -> {}", target.display());
    }
    writeln!(out, "{label:<5} {size:>10}  {name}")
}

fn describe(stats: &Stats) -> String {
    format!(
        "{} files, {} directories, {} links, {}",
        stats.files,
        stats.dirs,
        stats.links,
        human_size(stats.bytes)
    )
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
