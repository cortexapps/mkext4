//! The builder API: declare a namespace, seal it into a frozen layout,
//! then stream file contents (DESIGN.md §3).
//!
//! Memory model (DESIGN.md §3): one fixed-size record per inode slot, all
//! names in a single byte arena, children as per-directory vectors of
//! (name-ref, slot) — no per-entry heap strings.

mod htree;
mod seal;
mod writer;
mod xattr_build;

pub use seal::Layout;
pub use writer::{ImageWriter, Summary};

use crate::spec::{self, LINK_MAX};
use crate::{Error, Result};

/// Feature selection. Only one profile exists today; the type keeps the
/// door open without a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features(());

impl Features {
    /// has_journal, ext_attr, dir_index; filetype, extents, flex_bg;
    /// sparse_super, large_file, huge_file, dir_nlink, extra_isize,
    /// metadata_csum. See DESIGN.md §1.
    pub const LINUX_ROOTFS: Features = Features(());
}

/// Inode count policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeCount {
    /// mke2fs's default ratio: one inode per 16384 bytes.
    Auto,
    /// Exactly this many (rounded up to fill itable blocks).
    Exact(u32),
}

/// Seconds + nanoseconds since the epoch (ext4 range: DESIGN.md §9).
pub type Timespec = (i64, u32);

/// Per-inode metadata. `mode` carries permission bits only (0o7777);
/// the file type comes from the declaring call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    /// Permission bits (setuid/setgid/sticky included).
    pub mode: u16,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Modification time. Also the default for atime/ctime/crtime.
    pub mtime: Timespec,
    /// Access time (defaults to mtime).
    pub atime: Option<Timespec>,
    /// Inode-change time (defaults to mtime).
    pub ctime: Option<Timespec>,
    /// Creation time (defaults to mtime).
    pub crtime: Option<Timespec>,
}

impl Meta {
    /// `mode` + uid/gid, everything timestamped at `mtime`.
    pub fn new(mode: u16, uid: u32, gid: u32, mtime: Timespec) -> Meta {
        Meta {
            mode,
            uid,
            gid,
            mtime,
            atime: None,
            ctime: None,
            crtime: None,
        }
    }
}

/// Builder options (all determinism inputs are here — DESIGN.md §2).
#[derive(Debug, Clone)]
pub struct Options {
    /// Total image size in bytes (multiple of 4096). Required.
    pub size_bytes: u64,
    /// Filesystem UUID (never sampled).
    pub fs_uuid: [u8; 16],
    /// htree hash seed (`s_hash_seed`).
    pub hash_seed: [u32; 4],
    /// Superblock timestamps (`s_mkfs_time`, `s_wtime`, `s_lastcheck`)
    /// and the timestamp of fs-owned inodes (root default, lost+found,
    /// reserved inodes).
    pub epoch: i64,
    /// Inode count policy.
    pub inodes: InodeCount,
    /// Volume label (≤ 16 bytes).
    pub label: Option<String>,
    /// Reserved blocks percentage (mke2fs default 5).
    pub reserved_percent: u8,
    /// Journal size override in blocks (default: size-tiered, §15).
    pub journal_blocks: Option<u32>,
    /// Feature profile.
    pub features: Features,
}

/// Declared xattrs per builder slot.
pub(crate) type XattrDecls = std::collections::BTreeMap<u32, Vec<xattr_build::Attr>>;

/// Handle to a declared inode. Hardlinks are additional names for the
/// same handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InodeHandle(pub(crate) u32);

/// The root directory handle.
pub const ROOT: InodeHandle = InodeHandle(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NameRef {
    off: u32,
    len: u8,
}

#[derive(Debug)]
pub(crate) enum NodeKind {
    Dir {
        /// (name, child) in declaration order; tombstoned entries keep
        /// their slot but are skipped everywhere.
        children: Vec<(NameRef, u32, bool)>,
    },
    File {
        size: u64,
    },
    Sparse {
        /// Data segments as (byte offset, byte length), sorted, disjoint.
        data_segs: Vec<(u64, u64)>,
        /// Total logical size (data + holes).
        size: u64,
    },
    Symlink {
        target: Vec<u8>,
    },
    Special {
        /// Dirent file_type (CHR / BLK / FIFO / SOCK).
        ftype: u8,
        major: u32,
        minor: u32,
    },
}

/// One segment of a sparse file declaration, in logical order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparseSeg {
    /// Bytes supplied by `fill`.
    Data(u64),
    /// Absent blocks; read back as zeros; never filled.
    Hole(u64),
}

/// Kind of special inode for [`FsBuilder::mknod`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialKind {
    /// Character device.
    Char {
        /// Major number (≤ 4095).
        major: u32,
        /// Minor number (≤ 1048575).
        minor: u32,
    },
    /// Block device.
    Block {
        /// Major number (≤ 4095).
        major: u32,
        /// Minor number (≤ 1048575).
        minor: u32,
    },
    /// Named pipe.
    Fifo,
    /// Unix socket.
    Socket,
}

#[derive(Debug)]
pub(crate) struct Node {
    pub(crate) kind: NodeKind,
    pub(crate) meta: Meta,
    /// Dirent names pointing at this node (hardlink count for files;
    /// for dirs always 1 — extra links come from "." and children's "..").
    pub(crate) nlink: u32,
}

/// Phase 1: namespace declaration.
#[derive(Debug)]
pub struct FsBuilder {
    pub(crate) opts: Options,
    pub(crate) nodes: Vec<Node>,
    pub(crate) names: Vec<u8>,
    /// xattrs per slot: (name_index, name-after-prefix, value), few
    /// nodes have any, so a side map beats a per-node field.
    pub(crate) xattrs: XattrDecls,
    /// Total declared file bytes of all currently-linked files (upper
    /// bound; recomputed exactly at seal).
    declared_bytes: u64,
}

impl FsBuilder {
    /// Start declaring a namespace.
    pub fn new(opts: Options) -> Result<FsBuilder> {
        if opts.size_bytes == 0 || opts.size_bytes % 4096 != 0 {
            return Err(Error::Invalid(
                "size_bytes must be a positive multiple of 4096".into(),
            ));
        }
        if let Some(l) = &opts.label {
            if l.len() > 16 {
                return Err(Error::Invalid("label longer than 16 bytes".into()));
            }
        }
        if opts.reserved_percent > 50 {
            return Err(Error::Invalid("reserved_percent > 50".into()));
        }
        // The superblock's own timestamps are plain 32-bit fields.
        if opts.epoch < 0 || opts.epoch > i64::from(u32::MAX) {
            return Err(Error::Invalid(format!(
                "epoch {} outside the superblock's u32 range",
                opts.epoch
            )));
        }
        let root_meta = Meta::new(0o755, 0, 0, (opts.epoch, 0));
        Ok(FsBuilder {
            opts,
            nodes: vec![Node {
                kind: NodeKind::Dir {
                    children: Vec::new(),
                },
                meta: root_meta,
                nlink: 1,
            }],
            names: Vec::new(),
            xattrs: std::collections::BTreeMap::new(),
            declared_bytes: 0,
        })
    }

    fn intern(&mut self, name: &str) -> Result<NameRef> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() > 255 {
            return Err(Error::Invalid(format!(
                "name length {} (must be 1..=255)",
                bytes.len()
            )));
        }
        if bytes.contains(&b'/') || bytes.contains(&0) || name == "." || name == ".." {
            return Err(Error::Invalid(format!("invalid name {name:?}")));
        }
        let off = u32::try_from(self.names.len())
            .map_err(|_| Error::Invalid("name arena overflow".into()))?;
        self.names.extend_from_slice(bytes);
        Ok(NameRef {
            off,
            len: bytes.len() as u8,
        })
    }

    pub(crate) fn name(&self, r: NameRef) -> &[u8] {
        &self.names[r.off as usize..r.off as usize + usize::from(r.len)]
    }

    fn dir_children_mut(&mut self, dir: InodeHandle) -> Result<&mut Vec<(NameRef, u32, bool)>> {
        match self.nodes.get_mut(dir.0 as usize).map(|n| &mut n.kind) {
            Some(NodeKind::Dir { children }) => Ok(children),
            Some(_) => Err(Error::Invalid("parent is not a directory".into())),
            None => Err(Error::Invalid("invalid handle".into())),
        }
    }

    fn check_duplicate(&self, dir: InodeHandle, name: &str) -> Result<()> {
        let Some(NodeKind::Dir { children }) = self.nodes.get(dir.0 as usize).map(|n| &n.kind)
        else {
            return Err(Error::Invalid("parent is not a directory".into()));
        };
        for (nref, _, dead) in children {
            if !dead && self.name(*nref) == name.as_bytes() {
                return Err(Error::Invalid(format!(
                    "duplicate name {name:?} (remove it first)"
                )));
            }
        }
        Ok(())
    }

    fn add_entry(&mut self, dir: InodeHandle, name: &str, child: u32) -> Result<()> {
        self.check_duplicate(dir, name)?;
        let nref = self.intern(name)?;
        self.dir_children_mut(dir)?.push((nref, child, false));
        Ok(())
    }

    /// Declare a directory.
    pub fn mkdir(&mut self, parent: InodeHandle, name: &str, meta: Meta) -> Result<InodeHandle> {
        let slot = self.nodes.len() as u32;
        self.add_entry(parent, name, slot)?;
        self.nodes.push(Node {
            kind: NodeKind::Dir {
                children: Vec::new(),
            },
            meta,
            nlink: 1,
        });
        Ok(InodeHandle(slot))
    }

    /// Declare a regular file. `size` is final: `fill` must supply
    /// exactly this many bytes.
    pub fn file(
        &mut self,
        parent: InodeHandle,
        name: &str,
        meta: Meta,
        size: u64,
    ) -> Result<InodeHandle> {
        let slot = self.nodes.len() as u32;
        self.add_entry(parent, name, slot)?;
        self.nodes.push(Node {
            kind: NodeKind::File { size },
            meta,
            nlink: 1,
        });
        self.declared_bytes += size;
        Ok(InodeHandle(slot))
    }

    /// Declare a sparse file from a segment map. Every segment except the
    /// last must be a multiple of 4096 bytes (holes are whole absent
    /// blocks). `fill` later supplies only the `Data` bytes, in order.
    pub fn file_sparse(
        &mut self,
        parent: InodeHandle,
        name: &str,
        meta: Meta,
        segments: &[SparseSeg],
    ) -> Result<InodeHandle> {
        let mut data_segs = Vec::new();
        let mut offset = 0u64;
        for (i, seg) in segments.iter().enumerate() {
            let len = match *seg {
                SparseSeg::Data(l) => l,
                SparseSeg::Hole(l) => l,
            };
            if len == 0 {
                return Err(Error::Invalid("zero-length sparse segment".into()));
            }
            if i + 1 != segments.len() && len % 4096 != 0 {
                return Err(Error::Invalid(
                    "sparse segments must be block-aligned (except the last)".into(),
                ));
            }
            if let SparseSeg::Data(l) = *seg {
                // Merge adjacent data segments for a canonical map.
                match data_segs.last_mut() {
                    Some((o, dl)) if *o + *dl == offset => *dl += l,
                    _ => data_segs.push((offset, l)),
                }
            }
            offset += len;
        }
        let size = offset;
        let slot = self.nodes.len() as u32;
        self.add_entry(parent, name, slot)?;
        self.nodes.push(Node {
            kind: NodeKind::Sparse { data_segs, size },
            meta,
            nlink: 1,
        });
        self.declared_bytes += size;
        Ok(InodeHandle(slot))
    }

    /// Declare a symlink. Targets of ≤ 59 bytes are stored inline (fast
    /// symlink); longer ones occupy one block. Max 4095 bytes.
    pub fn symlink(
        &mut self,
        parent: InodeHandle,
        name: &str,
        target: &str,
        meta: Meta,
    ) -> Result<InodeHandle> {
        let t = target.as_bytes();
        if t.is_empty() || t.len() > 4095 || t.contains(&0) {
            return Err(Error::Invalid(format!(
                "symlink target length {} (must be 1..=4095, no NUL)",
                t.len()
            )));
        }
        let slot = self.nodes.len() as u32;
        self.add_entry(parent, name, slot)?;
        self.nodes.push(Node {
            kind: NodeKind::Symlink { target: t.to_vec() },
            meta,
            nlink: 1,
        });
        Ok(InodeHandle(slot))
    }

    /// Declare a device node, FIFO, or socket.
    pub fn mknod(
        &mut self,
        parent: InodeHandle,
        name: &str,
        meta: Meta,
        kind: SpecialKind,
    ) -> Result<InodeHandle> {
        let (ftype, major, minor) = match kind {
            SpecialKind::Char { major, minor } => (spec::file_type::CHR, major, minor),
            SpecialKind::Block { major, minor } => (spec::file_type::BLK, major, minor),
            SpecialKind::Fifo => (spec::file_type::FIFO, 0, 0),
            SpecialKind::Socket => (spec::file_type::SOCK, 0, 0),
        };
        if major > 0xFFF || minor > 0xF_FFFF {
            return Err(Error::Invalid(format!(
                "device numbers ({major}, {minor}) out of dev_t range"
            )));
        }
        let slot = self.nodes.len() as u32;
        self.add_entry(parent, name, slot)?;
        self.nodes.push(Node {
            kind: NodeKind::Special {
                ftype,
                major,
                minor,
            },
            meta,
            nlink: 1,
        });
        Ok(InodeHandle(slot))
    }

    /// Set an extended attribute on any live handle (including [`ROOT`]).
    /// Attributes are canonically sorted on disk, so declaration order
    /// does not affect the output; setting the same name again replaces
    /// the value.
    pub fn set_xattr(&mut self, handle: InodeHandle, name: &str, value: &[u8]) -> Result<()> {
        if self.nodes.get(handle.0 as usize).is_none() {
            return Err(Error::Invalid("invalid handle".into()));
        }
        let (index, suffix): (u8, &str) = if let Some(s) = name.strip_prefix("user.") {
            (1, s)
        } else if name == "system.posix_acl_access" {
            (2, "")
        } else if name == "system.posix_acl_default" {
            (3, "")
        } else if let Some(s) = name.strip_prefix("trusted.") {
            (4, s)
        } else if let Some(s) = name.strip_prefix("security.") {
            (6, s)
        } else if let Some(s) = name.strip_prefix("system.") {
            (7, s)
        } else {
            return Err(Error::Invalid(format!(
                "xattr name {name:?} has no recognized namespace"
            )));
        };
        if suffix.len() > 255 {
            return Err(Error::Invalid("xattr name too long".into()));
        }
        let list = self.xattrs.entry(handle.0).or_default();
        if let Some(e) = list
            .iter_mut()
            .find(|(i, n, _)| *i == index && n == suffix.as_bytes())
        {
            e.2 = value.to_vec();
        } else {
            list.push((index, suffix.as_bytes().to_vec(), value.to_vec()));
        }
        Ok(())
    }

    /// Add another name for an existing file (shared inode).
    pub fn hardlink(&mut self, parent: InodeHandle, name: &str, target: InodeHandle) -> Result<()> {
        match self.nodes.get(target.0 as usize).map(|n| &n.kind) {
            Some(NodeKind::Dir { .. }) => {
                return Err(Error::Invalid("hardlink to a directory".into()))
            }
            Some(_) => {}
            None => return Err(Error::Invalid("invalid handle".into())),
        }
        if self.nodes[target.0 as usize].nlink >= LINK_MAX {
            return Err(Error::Invalid(format!("more than {LINK_MAX} links")));
        }
        self.add_entry(parent, name, target.0)?;
        self.nodes[target.0 as usize].nlink += 1;
        Ok(())
    }

    /// Replace an inode's metadata (any live handle, including [`ROOT`]);
    /// the last call before seal wins.
    pub fn set_meta(&mut self, handle: InodeHandle, meta: Meta) -> Result<()> {
        self.nodes
            .get_mut(handle.0 as usize)
            .ok_or_else(|| Error::Invalid("invalid handle".into()))?
            .meta = meta;
        Ok(())
    }

    /// Remove `name` from `dir`. Removing a directory tombstones its
    /// entire subtree (DESIGN.md §3); files drop out entirely when their
    /// last link goes.
    pub fn remove(&mut self, dir: InodeHandle, name: &str) -> Result<()> {
        let children = match self.nodes.get(dir.0 as usize).map(|n| &n.kind) {
            Some(NodeKind::Dir { children }) => children,
            _ => return Err(Error::Invalid("parent is not a directory".into())),
        };
        let mut found = None;
        for (i, (nref, child, dead)) in children.iter().enumerate() {
            if !dead && self.name(*nref) == name.as_bytes() {
                found = Some((i, *child));
                break;
            }
        }
        let Some((idx, child)) = found else {
            return Err(Error::Invalid(format!("{name:?} not found")));
        };
        if let NodeKind::Dir { children } = &mut self.nodes[dir.0 as usize].kind {
            children[idx].2 = true;
        }
        match &self.nodes[child as usize].kind {
            NodeKind::Dir { .. } => self.remove_subtree(child),
            _ => self.unlink(child),
        }
        Ok(())
    }

    /// Drop one link of a non-directory node.
    fn unlink(&mut self, slot: u32) {
        let bytes = match &self.nodes[slot as usize].kind {
            NodeKind::File { size } => *size,
            NodeKind::Sparse { size, .. } => *size,
            _ => 0,
        };
        self.nodes[slot as usize].nlink -= 1;
        if self.nodes[slot as usize].nlink == 0 {
            self.declared_bytes -= bytes;
        }
    }

    fn remove_subtree(&mut self, dir_slot: u32) {
        self.nodes[dir_slot as usize].nlink = 0;
        let entries: Vec<(u32, bool)> = match &self.nodes[dir_slot as usize].kind {
            NodeKind::Dir { children } => children.iter().map(|&(_, c, d)| (c, d)).collect(),
            _ => unreachable!(),
        };
        if let NodeKind::Dir { children } = &mut self.nodes[dir_slot as usize].kind {
            for e in children.iter_mut() {
                e.2 = true;
            }
        }
        for (child, dead) in entries {
            if dead {
                continue;
            }
            match &self.nodes[child as usize].kind {
                NodeKind::Dir { .. } => self.remove_subtree(child),
                _ => self.unlink(child),
            }
        }
    }

    /// Phase 2: freeze the complete layout. Consumes the builder; every
    /// metadata byte and every future data offset is decided here.
    pub fn seal(self) -> Result<Layout> {
        seal::seal(self)
    }
}
