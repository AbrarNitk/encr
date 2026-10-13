//! Directory archiving as zstd-compressed tar streams. Everything streams; nothing is
//! buffered beyond the compressor's working window.

use std::{
    borrow::Cow,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use tar::{Archive, Builder, EntryType};
use walkdir::WalkDir;

// Each zstd worker holds a few tens of MiB, so cap them to keep memory predictable.
const MAX_COMPRESSION_THREADS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Link,
    Other,
}

impl From<EntryType> for EntryKind {
    fn from(entry_type: EntryType) -> Self {
        match entry_type {
            EntryType::Regular | EntryType::Continuous => Self::File,
            EntryType::Directory => Self::Directory,
            EntryType::Symlink | EntryType::Link => Self::Link,
            _ => Self::Other,
        }
    }
}

#[derive(Debug)]
pub struct EntryInfo {
    pub kind: EntryKind,
    pub path: PathBuf,
    pub size: u64,
    pub link_target: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    pub bytes: u64,
    pub skipped: Vec<PathBuf>,
}

impl Stats {
    fn record(&mut self, kind: EntryKind, size: u64) {
        match kind {
            EntryKind::File => {
                self.files += 1;
                self.bytes += size;
            }
            EntryKind::Directory => self.dirs += 1,
            EntryKind::Link => self.links += 1,
            EntryKind::Other => {}
        }
    }
}

/// Streams `root` into `sink` as a compressed tarball with paths relative to `root`.
/// Symlinks are stored as links, never followed; sockets and devices are skipped.
pub fn pack<W: Write>(root: &Path, sink: W, level: i32) -> Result<Stats> {
    let mut encoder = zstd::Encoder::new(sink, level).context("failed to initialise compressor")?;
    encoder
        .multithread(compression_threads())
        .context("failed to enable multithreaded compression")?;
    let mut builder = Builder::new(encoder);
    builder.follow_symlinks(false);

    let mut stats = Stats::default();
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry.context("failed to read input directory")?;
        let path = entry.path();
        let name = path
            .strip_prefix(root)
            .context("walked outside the input directory")?;
        if name.as_os_str().is_empty() {
            continue;
        }

        let file_type = entry.file_type();
        let (kind, size) = if file_type.is_dir() {
            (EntryKind::Directory, 0)
        } else if file_type.is_file() {
            let meta = entry
                .metadata()
                .with_context(|| format!("cannot read `{}`", path.display()))?;
            (EntryKind::File, meta.len())
        } else if file_type.is_symlink() {
            (EntryKind::Link, 0)
        } else {
            stats.skipped.push(path.to_path_buf());
            continue;
        };

        match kind {
            EntryKind::Directory => builder.append_dir(name, path),
            _ => builder.append_path_with_name(path, name),
        }
        .with_context(|| format!("failed to archive `{}`", path.display()))?;
        stats.record(kind, size);
    }

    let encoder = builder.into_inner().context("failed to finalise archive")?;
    encoder.finish().context("failed to finalise compression")?;
    Ok(stats)
}

/// Extracts a [`pack`] stream into `dest`. The tar crate refuses absolute paths, `..`
/// components and writes through symlinks that would escape `dest`.
pub fn unpack<R: BufRead>(source: R, dest: &Path) -> Result<()> {
    let mut archive = Archive::new(decompressor(source)?);
    archive.set_overwrite(true);
    archive.set_preserve_mtime(true);
    // Keeps rwx bits but drops setuid/setgid/sticky.
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);
    archive
        .unpack(dest)
        .with_context(|| format!("failed to extract into `{}`", dest.display()))?;
    drain(archive.into_inner())
}

/// Walks a [`pack`] stream, calling `visit` per entry, without touching the filesystem.
pub fn list<R: BufRead>(
    source: R,
    mut visit: impl FnMut(&EntryInfo) -> io::Result<()>,
) -> Result<Stats> {
    let mut archive = Archive::new(decompressor(source)?);
    let mut stats = Stats::default();

    for entry in archive.entries().context("failed to read archive")? {
        let entry = entry.context("failed to read archive entry")?;
        let info = EntryInfo {
            kind: entry.header().entry_type().into(),
            path: entry
                .path()
                .context("invalid path in archive")?
                .into_owned(),
            size: entry.size(),
            link_target: entry
                .link_name()
                .context("invalid link target in archive")?
                .map(Cow::into_owned),
        };
        visit(&info).context("failed to write listing")?;
        stats.record(info.kind, info.size);
    }

    drain(archive.into_inner())?;
    Ok(stats)
}

fn decompressor<'a, R: BufRead>(source: R) -> Result<zstd::Decoder<'a, R>> {
    zstd::Decoder::with_buffer(source).context("failed to initialise decompressor")
}

/// Reads past the tar end-of-archive marker so the compressed frame is fully consumed.
fn drain<R: BufRead>(mut decoder: zstd::Decoder<'_, R>) -> Result<()> {
    io::copy(&mut decoder, &mut io::sink()).context("failed to read archive trailer")?;
    Ok(())
}

fn compression_threads() -> u32 {
    let available = std::thread::available_parallelism().map_or(1, |n| n.get());
    u32::try_from(available.min(MAX_COMPRESSION_THREADS)).unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn pack_unpack_and_list_round_trip() {
        let src = tempfile::tempdir().unwrap();
        let root = src.path();
        fs::create_dir_all(root.join("nested/deeper")).unwrap();
        fs::create_dir(root.join("empty")).unwrap();
        fs::write(root.join("a.txt"), b"alpha").unwrap();
        fs::write(root.join("nested/deeper/b.bin"), vec![7u8; 100_000]).unwrap();
        fs::write(root.join("nested/empty.txt"), b"").unwrap();

        let mut packed = Vec::new();
        let stats = pack(root, &mut packed, 3).unwrap();
        assert_eq!((stats.files, stats.dirs, stats.bytes), (3, 3, 100_005));

        let dest = tempfile::tempdir().unwrap();
        unpack(packed.as_slice(), dest.path()).unwrap();
        assert_eq!(fs::read(dest.path().join("a.txt")).unwrap(), b"alpha");
        assert_eq!(
            fs::read(dest.path().join("nested/deeper/b.bin")).unwrap(),
            vec![7u8; 100_000]
        );
        assert!(dest.path().join("empty").is_dir());

        let mut paths = Vec::new();
        let listed = list(packed.as_slice(), |entry| {
            paths.push(entry.path.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!((listed.files, listed.dirs, listed.bytes), (3, 3, 100_005));
        assert!(paths.contains(&PathBuf::from("nested/deeper/b.bin")));
    }
}
