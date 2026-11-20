//! Unix-domain transport authenticated with kernel peer credentials.

use std::{
    fs, io,
    os::unix::fs::{DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use nix::unistd::Uid;
use tokio::net::{UnixListener, UnixStream};

pub type Server = UnixStream;
pub struct Listener {
    inner: UnixListener,
    path: PathBuf,
}

pub fn private_directory(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

impl Listener {
    pub async fn bind(path: &Path, personal: bool) -> io::Result<Self> {
        let listener = match UnixListener::bind(path) {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                // The caller holds the worker lifetime lock in the protected runtime directory.
                let file = fs::symlink_metadata(path)?;
                if !file.file_type().is_socket()
                    || file.uid() != Uid::effective().as_raw()
                    || !matches!(UnixStream::connect(path).await, Err(ref failure) if failure.kind() == io::ErrorKind::ConnectionRefused)
                {
                    return Err(error);
                }
                fs::remove_file(path)?;
                UnixListener::bind(path)?
            }
            other => other?,
        };
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if personal { 0o600 } else { 0o666 }),
        )?;
        Ok(Self {
            inner: listener,
            path: path.to_owned(),
        })
    }

    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "The Windows listener rotates its pending pipe instance on accept."
    )]
    pub async fn accept(&mut self) -> io::Result<Server> {
        self.inner.accept().await.map(|(stream, _)| stream)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _removed = fs::remove_file(&self.path);
    }
}

pub type Peer = String;

pub fn peer(stream: &Server) -> io::Result<Peer> {
    Ok(stream.peer_cred()?.uid().to_string())
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "The Windows peer token is resolved after the HTTP head is read."
)]
pub fn principal(peer: &Peer) -> io::Result<String> {
    Ok(peer.clone())
}

#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "libproc supplies the effective UID of the broker-attributed process."
)]
pub fn process_principal(pid: u32) -> Option<String> {
    let size = i32::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    // SAFETY: info has the exact writable capacity required by PROC_PIDTBSDINFO.
    let written = unsafe {
        libc::proc_pidinfo(
            i32::try_from(pid).ok()?,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    // SAFETY: proc_pidinfo initialized the complete native record.
    Some(unsafe { info.assume_init() }.pbi_uid.to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn process_principal(pid: u32) -> Option<String> {
    Some(fs::metadata(format!("/proc/{pid}")).ok()?.uid().to_string())
}
