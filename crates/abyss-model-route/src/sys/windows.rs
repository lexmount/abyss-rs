//! Named pipe authentication, Windows token identities and private state ACLs.

#![expect(
    unsafe_code,
    reason = "These wrappers bind Win32 handles, token buffers and security descriptors."
)]

use std::{
    ffi::{CStr, OsStr, c_void},
    fs, io,
    mem::{size_of, size_of_val},
    os::windows::{
        ffi::OsStrExt as _,
        fs::OpenOptionsExt as _,
        io::{
            AsHandle as _, AsRawHandle as _, FromRawHandle as _, IntoRawHandle as _, OwnedHandle,
        },
    },
    path::{Path, PathBuf},
    ptr,
};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, HANDLE, LocalFree},
    Security::{
        Authorization::{
            ConvertSidToStringSidA, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT,
            SetNamedSecurityInfoW,
        },
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, RevertToSelf,
        SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{FILE_FLAG_OVERLAPPED, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT},
    System::{
        Pipes::ImpersonateNamedPipeClient,
        Threading::{
            GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

pub type Client = NamedPipeClient;
pub type Server = NamedPipeServer;
pub type Peer = OwnedHandle;

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: the security APIs below return buffers allocated with LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}
fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

impl LocalAllocation {
    fn descriptor(sddl: &str) -> io::Result<Self> {
        let mut descriptor = ptr::null_mut();
        // SAFETY: the UTF-16 input is terminated, and the output points to writable handle storage.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(OsStr::new(sddl)).as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        } == 0_i32
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

pub fn private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let descriptor =
        LocalAllocation::descriptor("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)")?;
    let (mut present, mut defaulted, mut acl) = (0_i32, 0_i32, ptr::null_mut());
    // SAFETY: the descriptor stays live through SetNamedSecurityInfoW; all outputs are writable.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &raw mut present,
            &raw mut acl,
            &raw mut defaulted,
        )
    } == 0_i32
        || present == 0_i32
        || acl.is_null()
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the directory name is terminated and the DACL belongs to the live descriptor.
    let result = unsafe {
        SetNamedSecurityInfoW(
            wide(path.as_os_str()).as_ptr(),
            SE_FILE_OBJECT,
            PROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    };
    if result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result.cast_signed()))
    }
}

pub struct Listener {
    path: PathBuf,
    next: NamedPipeServer,
}

impl Listener {
    pub fn bind(path: &Path, _personal: bool) -> std::future::Ready<io::Result<Self>> {
        std::future::ready(Self::instance(path, true).map(|next| Self {
            path: path.to_owned(),
            next,
        }))
    }

    fn instance(path: &Path, first: bool) -> io::Result<Server> {
        // Authenticated users can send/receive data and read the pipe owner. They
        // cannot create another pipe instance (FILE_APPEND_DATA shares that bit).
        let owner = process_principal(std::process::id())
            .ok_or_else(|| io::Error::other("unknown routing service owner"))?;
        let sd = LocalAllocation::descriptor(&format!(
            "O:{owner}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x120003;;;AU)"
        ))?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(io::Error::other)?,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        // SAFETY: SECURITY_ATTRIBUTES and its descriptor live throughout synchronous creation.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(path, (&raw mut attributes).cast())
        }
    }

    pub async fn accept(&mut self) -> io::Result<Server> {
        self.next.connect().await?;
        let next = Self::instance(&self.path, false)?;
        Ok(std::mem::replace(&mut self.next, next))
    }
}

pub fn peer(stream: &Server) -> io::Result<Peer> {
    stream.as_handle().try_clone_to_owned()
}

pub fn principal(peer: &Peer) -> io::Result<String> {
    // SAFETY: peer is the live server endpoint after HTTP request headers have been read.
    if unsafe { ImpersonateNamedPipeClient(peer.as_raw_handle()) } == 0_i32 {
        return Err(io::Error::last_os_error());
    }
    let mut raw = ptr::null_mut();
    // SAFETY: only this thread's identification token is opened during impersonation.
    let thread = unsafe { GetCurrentThread() };
    // SAFETY: thread denotes the current impersonating thread; raw is a valid output slot.
    let opened = unsafe { OpenThreadToken(thread, TOKEN_QUERY, 1, &raw mut raw) };
    let err = io::Error::last_os_error();
    // SAFETY: restore the service identity on this same thread before doing any other work.
    if unsafe { RevertToSelf() } == 0_i32 {
        std::process::abort();
    }
    if opened == 0_i32 {
        return Err(err);
    }
    // SAFETY: successful OpenThreadToken transfers ownership of this handle.
    token_sid(&unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn token_sid(token: &OwnedHandle) -> io::Result<String> {
    let mut needed = 0;
    // SAFETY: zero-size query asks for the required byte count only.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &raw mut needed,
        )
    };
    let words = usize::try_from(needed)
        .map_err(io::Error::other)?
        .div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    if words == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: word storage is aligned for TOKEN_USER and contains at least 'needed' bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    } == 0_i32
    {
        return Err(io::Error::last_os_error());
    }
    if size_of_val(buffer.as_slice()) < size_of::<TOKEN_USER>() {
        return Err(io::Error::other("invalid token user"));
    }
    // SAFETY: GetTokenInformation initialized TOKEN_USER and its SID in this buffer.
    sid_text(unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}

fn sid_text(sid: *mut c_void) -> io::Result<String> {
    let mut raw = ptr::null_mut();
    // SAFETY: callers hold the native buffer containing this validated SID.
    if unsafe { ConvertSidToStringSidA(sid, &raw mut raw) } == 0_i32 {
        return Err(io::Error::last_os_error());
    }
    let _storage = LocalAllocation(raw.cast());
    // SAFETY: the API returned a NUL-terminated SID owned by the live allocation.
    unsafe { CStr::from_ptr(raw.cast()) }
        .to_str()
        .map(str::to_owned)
        .map_err(io::Error::other)
}

pub fn process_principal(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess returns a uniquely owned process handle or null.
    let proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if proc.is_null() {
        return None;
    }
    // SAFETY: ownership was transferred by OpenProcess.
    let proc = unsafe { OwnedHandle::from_raw_handle(proc) };
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: proc is valid and the output handle slot is writable.
    if unsafe { OpenProcessToken(proc.as_raw_handle(), TOKEN_QUERY, &raw mut raw) } == 0_i32 {
        return None;
    }
    // SAFETY: OpenProcessToken returned an owned handle.
    token_sid(&unsafe { OwnedHandle::from_raw_handle(raw) }).ok()
}

pub fn connect(path: &Path, personal: bool) -> std::future::Ready<io::Result<Client>> {
    std::future::ready(connect_pipe(path, personal))
}

fn connect_pipe(path: &Path, personal: bool) -> io::Result<Client> {
    let file = fs::OpenOptions::new()
        .access_mode(0x0012_0003)
        .custom_flags(FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
        .open(path)?;
    let (mut owner, mut sd) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: the pipe is open for READ_CONTROL; owner is inside the returned descriptor.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut sd,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    let _allocation = LocalAllocation(sd);
    let trusted = if personal {
        process_principal(std::process::id())
            .ok_or_else(|| io::Error::other("unknown route owner"))?
    } else {
        "S-1-5-18".into()
    };
    if sid_text(owner)? != trusted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unexpected routing service owner.",
        ));
    }
    // SAFETY: transfer the uniquely owned overlapped named pipe handle to Tokio.
    unsafe { NamedPipeClient::from_raw_handle(file.into_raw_handle()) }
}

pub fn personal_endpoint(profile: &Path) -> PathBuf {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(profile.as_os_str().as_encoded_bytes());
    PathBuf::from(format!(r"\\.\pipe\abyss-model-route-{digest:x}"))
}
