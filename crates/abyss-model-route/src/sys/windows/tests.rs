//! Exercise the real control pipe using only its authenticated-user access grant.

use super::*;
use http_body_util::BodyExt as _;
use std::{os::windows::io::IntoRawHandle as _, sync::Arc, time::Duration};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{ConvertStringSidToSidW, GetSecurityInfo},
        CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, ImpersonateLoggedOnUser,
        OWNER_SECURITY_INFORMATION, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING,
        READ_CONTROL, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, SYNCHRONIZE, WRITE_DAC,
        WRITE_OWNER,
    },
    System::Threading::GetCurrentProcess,
};

struct AuthenticatedClient(OwnedHandle);

impl AuthenticatedClient {
    fn new() -> Self {
        // SAFETY: GetCurrentProcess returns a borrowed pseudo-handle for this process.
        let process = unsafe { GetCurrentProcess() };
        let mut token = ptr::null_mut();
        // SAFETY: process is valid and token is writable output storage.
        let opened =
            unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &raw mut token) };
        assert_ne!(
            opened,
            0_i32,
            "open test token: {}",
            io::Error::last_os_error()
        );
        // SAFETY: OpenProcessToken returned a uniquely owned token handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut sid = ptr::null_mut();
        // SAFETY: the SID string is terminated and sid is writable output storage.
        let converted =
            unsafe { ConvertStringSidToSidW(wide(OsStr::new("S-1-5-11")).as_ptr(), &raw mut sid) };
        assert_ne!(converted, 0_i32, "create authenticated-users SID");
        let sid = LocalAllocation(sid);
        let restriction = SID_AND_ATTRIBUTES {
            Sid: sid.0,
            Attributes: 0,
        };
        let mut restricted = ptr::null_mut();
        // A second access check must pass using only AU, even when tests run as
        // the pipe owner or an administrator. No new account or elevation is needed.
        // SAFETY: token and the restriction SID remain live; all arrays/counts match.
        let created = unsafe {
            CreateRestrictedToken(
                token.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                0,
                ptr::null(),
                0,
                ptr::null(),
                1,
                &raw const restriction,
                &raw mut restricted,
            )
        };
        assert_ne!(
            created,
            0_i32,
            "restrict test token: {}",
            io::Error::last_os_error()
        );
        // SAFETY: CreateRestrictedToken transferred a uniquely owned handle.
        Self(unsafe { OwnedHandle::from_raw_handle(restricted) })
    }

    fn run<T, F: FnOnce() -> T>(&self, operation: F) -> T {
        // SAFETY: the restricted token is live; the guard restores this same thread.
        let impersonated = unsafe { ImpersonateLoggedOnUser(self.0.as_raw_handle()) };
        assert_ne!(
            impersonated,
            0_i32,
            "impersonate: {}",
            io::Error::last_os_error()
        );
        let _guard = Impersonation;
        // This synchronous scope must never suspend while impersonating.
        operation()
    }
}

struct Impersonation;

impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: this guard drops on the thread that impersonated the test client.
        if unsafe { RevertToSelf() } == 0_i32 {
            std::process::abort();
        }
    }
}

fn open_client(path: &Path, access: u32) -> io::Result<OwnedHandle> {
    // Use the same narrow access request as native desktop clients. CreateFileW
    // also requires FILE_READ_ATTRIBUTES, even though it is not requested here.
    // SAFETY: the path is terminated; no borrowed handles or attribute pointers are passed.
    let handle = unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            access,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful CreateFileW transferred a uniquely owned handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}

fn pipe_path(directory: &Path) -> PathBuf {
    PathBuf::from(format!(
        r"\\.\pipe\abyss-route-acl-{}",
        directory.file_name().unwrap().to_string_lossy()
    ))
}

#[tokio::test]
async fn authenticated_user_can_query_an_empty_catalog() {
    let directory = tempfile::tempdir().unwrap();
    let path = pipe_path(directory.path());
    let listener = Listener::bind(&path, false).await.unwrap();
    let expected_owner = process_principal(std::process::id()).unwrap();
    let client = AuthenticatedClient::new().run(|| {
        open_client(
            &path,
            FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL | SYNCHRONIZE,
        )
        .expect("authenticated users must be able to open the management pipe")
    });
    // Restoring the thread token does not expand the handle's granted rights.
    let (mut owner, mut descriptor) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: the handle grants READ_CONTROL, and outputs point to writable storage.
    let status = unsafe {
        GetSecurityInfo(
            client.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    assert_eq!(
        status, ERROR_SUCCESS,
        "clients can authenticate the pipe owner"
    );
    let _descriptor = LocalAllocation(descriptor);
    assert_eq!(sid_text(owner).unwrap(), expected_owner);
    // SAFETY: client owns a connected, overlapped pipe; ownership transfers to Tokio.
    let client = unsafe {
        tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(client.into_raw_handle())
    }
    .unwrap();
    let store = crate::store::Store::open(directory.path().to_owned(), std::process::id()).unwrap();
    let server = tokio::spawn(crate::rest::serve(listener, Arc::new(store)));
    let response = tokio::time::timeout(Duration::from_secs(5), async {
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(client))
                .await
                .unwrap();
        tokio::spawn(connection);
        let request = hyper::Request::builder()
            .uri(crate::rest::STATE)
            .header("host", "localhost")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        )
    })
    .await;
    server.abort();
    let (status, state) = response.expect("management request should finish");
    assert_eq!(status, hyper::StatusCode::OK);
    assert_eq!(state["catalog"]["providers"], serde_json::json!({}));
    assert_eq!(state["selections"], serde_json::json!({}));
}

#[tokio::test]
async fn authenticated_user_cannot_take_over_the_pipe() {
    let directory = tempfile::tempdir().unwrap();
    let path = pipe_path(directory.path());
    let _listener = Listener::bind(&path, false).await.unwrap();
    AuthenticatedClient::new().run(|| {
        for access in [GENERIC_WRITE, WRITE_DAC, WRITE_OWNER] {
            let error = open_client(&path, access).expect_err("privileged access must be denied");
            assert_eq!(
                error.raw_os_error(),
                Some(ERROR_ACCESS_DENIED.cast_signed())
            );
        }
        let error = ServerOptions::new()
            .create(&path)
            .expect_err("authenticated users cannot create another control pipe instance");
        assert_eq!(
            error.raw_os_error(),
            Some(ERROR_ACCESS_DENIED.cast_signed())
        );
    });
}
