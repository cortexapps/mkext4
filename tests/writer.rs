//! Writer gates (DESIGN.md §19): every image passes `e2fsck -fn`, the
//! reader round-trips it with zero verify() issues, the sink contract
//! holds exactly, and the output is byte-deterministic (and sensitive).

use std::io::Read;
use std::path::{Path, PathBuf};

use streamext4::reader::Fs;
use streamext4::sink::{CheckingSink, VecSink};
use streamext4::spec;
use streamext4::{Features, FsBuilder, InodeCount, Meta, Options, ROOT};

const UUID: [u8; 16] = [
    0xd0, 0xd0, 0xca, 0xca, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];
const SEED: [u32; 4] = [0xefbe_adde, 0xad4e_adde, 0xadde_ad8e, 0x0000_efbe];
const EPOCH: i64 = 1_704_067_200;

fn options(size: u64) -> Options {
    Options {
        size_bytes: size,
        fs_uuid: UUID,
        hash_seed: SEED,
        epoch: EPOCH,
        inodes: InodeCount::Auto,
        label: Some("strext4".into()),
        reserved_percent: 5,
        journal_blocks: None,
        features: Features::LINUX_ROOTFS,
    }
}

fn meta(mode: u16) -> Meta {
    Meta::new(mode, 0, 0, (EPOCH, 0))
}

/// Deterministic pattern source.
struct Pattern {
    remaining: u64,
    counter: u64,
}

impl Pattern {
    fn new(len: u64, seed: u64) -> Pattern {
        Pattern {
            remaining: len,
            counter: seed,
        }
    }
}

impl Read for Pattern {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = (self.remaining).min(buf.len() as u64) as usize;
        for b in &mut buf[..n] {
            self.counter = self
                .counter
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1);
            *b = (self.counter >> 33) as u8;
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

fn pattern_bytes(len: u64, seed: u64) -> Vec<u8> {
    let mut v = Vec::new();
    Pattern::new(len, seed).read_to_end(&mut v).unwrap();
    v
}

/// Build a representative namespace and return the image bytes.
fn build_basic(size: u64, mtime_tweak: i64) -> Vec<u8> {
    let mut b = FsBuilder::new(options(size)).unwrap();
    b.set_meta(ROOT, meta(0o755)).unwrap();
    let usr = b.mkdir(ROOT, "usr", meta(0o755)).unwrap();
    let bin = b.mkdir(usr, "bin", meta(0o755)).unwrap();
    let mut m = meta(0o644);
    m.mtime = (EPOCH + mtime_tweak, 500_000_000);
    let cat = b.file(bin, "cat", m, 8_192).unwrap();
    b.hardlink(bin, "dog", cat).unwrap();
    b.file(usr, "empty", meta(0o600), 0).unwrap();
    let setuid = b.file(ROOT, "setuid", meta(0o4755), 100).unwrap();
    // A file whose final block is partial.
    let odd = b.file(usr, "odd", meta(0o644), 5_000).unwrap();
    // Many names to force a multi-block linear directory.
    let big = b.mkdir(ROOT, "big", meta(0o755)).unwrap();
    for i in 0..200 {
        b.file(big, &format!("entry_{i:05}_padding"), meta(0o644), 0)
            .unwrap();
    }
    // Whiteout: declare then remove a populated subtree.
    let tmp = b.mkdir(ROOT, "tmp", meta(0o755)).unwrap();
    b.file(tmp, "junk", meta(0o644), 4096).unwrap();
    b.remove(ROOT, "tmp").unwrap();
    // Removed and re-added name.
    b.file(ROOT, "twice", meta(0o644), 0).unwrap();
    b.remove(ROOT, "twice").unwrap();
    let twice = b.file(ROOT, "twice", meta(0o600), 42).unwrap();

    let layout = b.seal().unwrap();
    let mut sink = CheckingSink::new(VecSink::default());
    let mut w = layout.writer(&mut sink).unwrap();
    w.fill(cat, &mut Pattern::new(8_192, 1)).unwrap();
    w.fill(odd, &mut Pattern::new(5_000, 2)).unwrap();
    w.fill(twice, &mut Pattern::new(42, 3)).unwrap();
    // Out-of-declaration-order fill: legal, only loses ascending offsets.
    w.fill(setuid, &mut Pattern::new(100, 4)).unwrap();
    let summary = w.finish().unwrap();
    assert_eq!(summary.image_len, size);
    let inner = sink.finish(size).expect("exactly-once coverage");
    inner.buf.clone()
}

fn e2fsprogs_sbin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("E2FSPROGS_SBIN") {
        return Some(PathBuf::from(p));
    }
    for cand in [
        "/opt/homebrew/opt/e2fsprogs/sbin",
        "/usr/local/opt/e2fsprogs/sbin",
    ] {
        if Path::new(cand).join("e2fsck").exists() {
            return Some(PathBuf::from(cand));
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find(|dir| dir.join("e2fsck").exists())
}

/// `e2fsck -fn` must exit 0 with no complaints.
fn assert_fsck_clean(image: &[u8], tag: &str) {
    let Some(sbin) = e2fsprogs_sbin() else {
        eprintln!("SKIP fsck gate: e2fsprogs not found");
        return;
    };
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&dir).unwrap();
    let img = dir.join(format!("{tag}.img"));
    std::fs::write(&img, image).unwrap();
    let out = std::process::Command::new(sbin.join("e2fsck"))
        .arg("-fn")
        .arg(&img)
        .output()
        .expect("running e2fsck");
    assert!(
        out.status.success(),
        "{tag}: e2fsck -fn failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn basic_image_fsck_clean_and_readable() {
    let size = 64 << 20; // 16384 blocks
    let image = build_basic(size, 0);
    assert_eq!(image.len() as u64, size);
    assert_fsck_clean(&image, "writer_basic");

    let fs = Fs::open(&image[..]).expect("reader opens our image");
    let issues = fs.verify().expect("verify runs");
    assert!(
        issues.is_empty(),
        "verify issues: {:?}",
        &issues[..issues.len().min(5)]
    );

    // Content round-trips.
    let cat = fs.resolve("/usr/bin/cat").unwrap();
    assert_eq!(fs.read_file(cat).unwrap(), pattern_bytes(8_192, 1));
    let odd = fs.resolve("/usr/odd").unwrap();
    assert_eq!(fs.read_file(odd).unwrap(), pattern_bytes(5_000, 2));
    let twice = fs.resolve("/twice").unwrap();
    assert_eq!(fs.read_file(twice).unwrap(), pattern_bytes(42, 3));

    // Hardlink shares the inode, nlink 2.
    let dog = fs.resolve("/usr/bin/dog").unwrap();
    assert_eq!(dog, cat);
    assert_eq!(fs.inode(cat).unwrap().links_count, 2);

    // Metadata.
    let setuid = fs.inode(fs.resolve("/setuid").unwrap()).unwrap();
    assert_eq!(setuid.mode & 0o7777, 0o4755);
    let cat_inode = fs.inode(cat).unwrap();
    let (mt, ns) = spec::Inode::timestamp(cat_inode.mtime, cat_inode.mtime_extra);
    assert_eq!((mt, ns), (EPOCH, 500_000_000));

    // Whiteout semantics: /tmp is gone entirely; /twice was re-added.
    assert!(fs.lookup(spec::ROOT_INO, b"tmp").unwrap().is_none());
    let twice_inode = fs.inode(twice).unwrap();
    assert_eq!(twice_inode.mode & 0o7777, 0o600);
    assert_eq!(twice_inode.size, 42);

    // Multi-block linear dir reads completely.
    let big = fs.resolve("/big").unwrap();
    let n = fs
        .read_dir(big)
        .unwrap()
        .iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .count();
    assert_eq!(n, 200);

    // lost+found per convention.
    let lf = fs.resolve("/lost+found").unwrap();
    assert_eq!(lf, 11);
    let lf_inode = fs.inode(lf).unwrap();
    assert_eq!(lf_inode.size, 4 * 4096);
    assert_eq!(lf_inode.mode & 0o7777, 0o700);
}

#[test]
fn deterministic_and_sensitive() {
    let size = 32 << 20;
    let a = build_basic(size, 0);
    let b = build_basic(size, 0);
    assert_eq!(a, b, "identical inputs must produce identical bytes");
    let c = build_basic(size, 1); // one mtime changed by one second
    assert_ne!(a, c, "a changed mtime must change the output");
}

#[test]
fn empty_namespace_image() {
    let size = 16 << 20;
    let b = FsBuilder::new(options(size)).unwrap();
    let layout = b.seal().unwrap();
    let mut sink = CheckingSink::new(VecSink::default());
    let w = layout.writer(&mut sink).unwrap();
    w.finish().unwrap();
    let image = sink.finish(size).unwrap().buf.clone();
    assert_fsck_clean(&image, "writer_empty");
    let fs = Fs::open(&image[..]).unwrap();
    assert!(fs.verify().unwrap().is_empty());
    assert_eq!(fs.resolve("/lost+found").unwrap(), 11);
}

#[test]
fn odd_geometry_multiple_groups() {
    // 3.5 groups + a file crossing the group-1 backup: forces split
    // extents and exercises INODE_UNINIT groups and backup emission.
    let size = 114688 * 4096; // 3.5 groups
    let mut b = FsBuilder::new(options(size)).unwrap();
    let f = b.file(ROOT, "spanner", meta(0o644), 300 << 20).unwrap();
    let layout = b.seal().unwrap();
    let extents = layout.extents(f);
    assert!(extents.len() > 1, "file must split across reserved runs");
    let mut sink = CheckingSink::new(VecSink::default());
    let mut w = layout.writer(&mut sink).unwrap();
    w.fill(f, &mut Pattern::new(300 << 20, 9)).unwrap();
    w.finish().unwrap();
    let image = sink.finish(size).unwrap().buf.clone();
    assert_fsck_clean(&image, "writer_span");
    let fs = Fs::open(&image[..]).unwrap();
    assert!(fs.verify().unwrap().is_empty());
    let ino = fs.resolve("/spanner").unwrap();
    let inode = fs.inode(ino).unwrap();
    let fx = fs.extents(ino, &inode).unwrap();
    assert!(fx.len() > 1);
    // Spot-check content at extent boundaries.
    let want = pattern_bytes(300 << 20, 9);
    let mut got = vec![0u8; 1 << 16];
    for probe in [0u64, (32768 * 4096) - 7, 150 << 20, (300 << 20) - 1] {
        let n = fs.read_file_at(&inode, &fx, probe, &mut got).unwrap();
        assert!(n > 0);
        assert_eq!(
            got[..n],
            want[probe as usize..probe as usize + n],
            "content mismatch at {probe}"
        );
    }
}

#[test]
fn extent_tree_depth_one() {
    // A 640 MiB file in a 1 GiB image: five 32768-block extents plus
    // backup-run splits force > 4 extents => a depth-1 extent tree.
    let size = 1 << 30;
    let len = 640u64 << 20;
    let mut b = FsBuilder::new(options(size)).unwrap();
    let f = b.file(ROOT, "huge", meta(0o644), len).unwrap();
    let layout = b.seal().unwrap();
    assert!(layout.extents(f).len() > 4, "must exceed the inline root");
    let mut sink = CheckingSink::new(VecSink::default());
    let mut w = layout.writer(&mut sink).unwrap();
    w.fill(f, &mut Pattern::new(len, 11)).unwrap();
    w.finish().unwrap();
    let image = sink.finish(size).unwrap().buf.clone();
    assert_fsck_clean(&image, "writer_tree");
    let fs = Fs::open(&image[..]).unwrap();
    assert!(fs.verify().unwrap().is_empty());
    let ino = fs.resolve("/huge").unwrap();
    let inode = fs.inode(ino).unwrap();
    // Root must be an index node now.
    let root = inode.extent_root().unwrap();
    let h = spec::ExtentHeader::decode(root).unwrap();
    assert_eq!(h.depth, 1);
    // Content spot checks across the whole range.
    let fx = fs.extents(ino, &inode).unwrap();
    let mut got = vec![0u8; 4096];
    for probe in [0u64, len / 2, len - 4096] {
        fs.read_file_at(&inode, &fx, probe, &mut got).unwrap();
        let want = pattern_at(len, 11, probe, got.len());
        assert_eq!(got, want, "content at {probe}");
    }
}

/// Recompute `len` bytes of the pattern at an offset without holding the
/// whole stream.
fn pattern_at(total: u64, seed: u64, offset: u64, len: usize) -> Vec<u8> {
    let mut p = Pattern::new(total, seed);
    let mut skip = vec![0u8; 1 << 20];
    let mut remaining = offset;
    while remaining > 0 {
        let n = remaining.min(skip.len() as u64) as usize;
        p.read_exact(&mut skip[..n]).unwrap();
        remaining -= n as u64;
    }
    let mut out = vec![0u8; len];
    p.read_exact(&mut out).unwrap();
    out
}

#[test]
fn unfilled_file_errors_and_poisoning() {
    let size = 16 << 20;
    let mut b = FsBuilder::new(options(size)).unwrap();
    let f = b.file(ROOT, "f", meta(0o644), 4096).unwrap();
    let layout = b.seal().unwrap();
    // finish() without fill must error.
    let mut sink = VecSink::default();
    let w = layout.writer(&mut sink).unwrap();
    assert!(w.finish().is_err());
    // Short fill poisons.
    let mut sink = VecSink::default();
    let mut w = layout.writer(&mut sink).unwrap();
    assert!(w.fill(f, &mut Pattern::new(100, 0)).is_err()); // only 100 of 4096
    assert!(w.finish().is_err());
}
