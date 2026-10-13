//! Path resolution and crash-safe output staging that behave the same on Windows, macOS and Linux.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use tempfile::{Builder, NamedTempFile, TempDir};

const STAGING_PREFIX: &str = ".encr-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    File,
    Directory,
}

/// Canonicalises an existing path. `dunce` drops the Windows `\\?\` verbatim prefix
/// whenever the plain form is equivalent, keeping paths readable and tool-friendly.
pub fn canonicalize(path: &Path) -> Result<PathBuf> {
    dunce::canonicalize(path).with_context(|| format!("cannot access `{}`", path.display()))
}

pub fn classify_input(path: &Path) -> Result<(PathBuf, InputKind)> {
    let path = canonicalize(path)?;
    let meta = fs::metadata(&path).with_context(|| format!("cannot read `{}`", path.display()))?;
    let kind = if meta.is_dir() {
        InputKind::Directory
    } else if meta.is_file() {
        InputKind::File
    } else {
        bail!(
            "`{}` is neither a regular file nor a directory",
            path.display()
        );
    };
    Ok((path, kind))
}

/// Absolute form of a path that may not exist yet: canonical parent joined with the final name.
pub fn resolve_output(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .with_context(|| format!("`{}` does not name a file or directory", path.display()))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = dunce::canonicalize(parent)
        .with_context(|| format!("output directory `{}` does not exist", parent.display()))?;
    Ok(parent.join(name))
}

pub fn ensure_absent(path: &Path, force: bool) -> Result<()> {
    if !force && path.symlink_metadata().is_ok() {
        bail!(
            "`{}` already exists (use --force to overwrite)",
            path.display()
        );
    }
    Ok(())
}

/// Guards against overwriting the input, or an archive swallowing itself while it grows.
pub fn ensure_not_inside(output: &Path, input: &Path) -> Result<()> {
    if output == input {
        bail!("input and output are the same path: `{}`", input.display());
    }
    if output.starts_with(input) {
        bail!(
            "output `{}` must not be inside the input directory `{}`",
            output.display(),
            input.display()
        );
    }
    Ok(())
}

/// A hidden temp file beside the destination, moved into place only on [`StagedFile::commit`].
/// Failures and interruptions never leave a partial output behind.
pub struct StagedFile {
    tmp: NamedTempFile,
    dest: PathBuf,
}

impl StagedFile {
    pub fn create(dest: &Path) -> Result<Self> {
        let dir = staging_dir(dest)?;
        let tmp = Builder::new()
            .prefix(STAGING_PREFIX)
            .suffix(".tmp")
            .tempfile_in(dir)
            .with_context(|| format!("cannot create a file in `{}`", dir.display()))?;
        Ok(Self {
            tmp,
            dest: dest.to_path_buf(),
        })
    }

    pub fn commit(self, overwrite: bool) -> Result<()> {
        self.tmp
            .as_file()
            .sync_all()
            .context("failed to flush output to disk")?;
        let persisted = if overwrite {
            self.tmp.persist(&self.dest)
        } else {
            self.tmp.persist_noclobber(&self.dest)
        };
        persisted
            .map_err(|err| err.error)
            .with_context(|| format!("failed to write `{}`", self.dest.display()))?;
        Ok(())
    }
}

impl Write for StagedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tmp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tmp.flush()
    }
}

/// Directory counterpart of [`StagedFile`].
pub struct StagedDir {
    tmp: TempDir,
    dest: PathBuf,
}

impl StagedDir {
    pub fn create(dest: &Path) -> Result<Self> {
        let dir = staging_dir(dest)?;
        let tmp = Builder::new()
            .prefix(STAGING_PREFIX)
            .tempdir_in(dir)
            .with_context(|| format!("cannot create a directory in `{}`", dir.display()))?;
        Ok(Self {
            tmp,
            dest: dest.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        self.tmp.path()
    }

    pub fn commit(self) -> Result<()> {
        let staged = self.tmp.keep();
        fs::rename(&staged, &self.dest)
            .inspect_err(|_| {
                let _ = fs::remove_dir_all(&staged);
            })
            .with_context(|| format!("failed to create `{}`", self.dest.display()))
    }
}

fn staging_dir(dest: &Path) -> Result<&Path> {
    dest.parent()
        .with_context(|| format!("`{}` has no parent directory", dest.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_resolves_against_canonical_parent() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = resolve_output(&dir.path().join("out.enc")).unwrap();
        assert_eq!(resolved, canonicalize(dir.path()).unwrap().join("out.enc"));
    }

    #[test]
    fn output_with_missing_parent_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(resolve_output(&dir.path().join("missing").join("out.enc")).is_err());
    }

    #[test]
    fn output_inside_input_is_rejected() {
        let input = Path::new("data").join("photos");
        assert!(ensure_not_inside(&input.join("backup.enc"), &input).is_err());
        assert!(ensure_not_inside(&input, &input).is_err());
        assert!(ensure_not_inside(&Path::new("data").join("photos.enc"), &input).is_ok());
    }

    #[test]
    fn staged_file_appears_only_on_commit() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.bin");
        let mut staged = StagedFile::create(&dest).unwrap();
        staged.write_all(b"payload").unwrap();
        assert!(!dest.exists());
        staged.commit(false).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"payload");
    }

    #[test]
    fn dropped_staging_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        drop(StagedFile::create(&dir.path().join("out.bin")).unwrap());
        drop(StagedDir::create(&dir.path().join("out")).unwrap());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
