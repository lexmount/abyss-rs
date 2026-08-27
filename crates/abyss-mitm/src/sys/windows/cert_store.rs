//! Safe wrappers for Windows certificate store APIs.
//!
//! This module preserves native Windows certificate-store semantics while
//! hiding raw handles, certificate context ownership, and `crypt32` FFI calls
//! from the MITM business layer.

#![expect(
    unsafe_code,
    reason = "Windows certificate stores are exposed through raw crypt32 FFI."
)]

use std::{ffi::c_void, fmt, mem, ptr::NonNull, slice};

use windows::{
    Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
        CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_SYSTEM_STORE_LOCAL_MACHINE, CertAddEncodedCertificateToStore, CertCloseStore,
        CertDeleteCertificateFromStore, CertEnumCertificatesInStore, CertFreeCertificateContext,
        CertOpenStore, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    },
    core::Error as WindowsError,
};

const ROOT_STORE_NAME: &[u16] = &[82_u16, 79_u16, 79_u16, 84_u16, 0_u16];

/// Windows system certificate store location.
#[derive(Debug, Clone, Copy)]
pub enum SystemStoreLocation {
    /// Current user's certificate store.
    CurrentUser,
    /// Local machine certificate store.
    LocalMachine,
}

/// Windows system certificate store name.
#[derive(Debug, Clone, Copy)]
pub enum SystemStoreName {
    /// Windows trusted root certification authorities store.
    Root,
}

/// Certificate encoding flags accepted by crypt32.
#[derive(Debug, Clone, Copy)]
pub enum CertificateEncoding {
    /// X.509 certificate or PKCS#7 container.
    X509OrPkcs7,
}

/// Add disposition for `CertAddEncodedCertificateToStore`.
#[derive(Debug, Clone, Copy)]
pub enum AddDisposition {
    /// Replace an existing matching certificate entry.
    ReplaceExisting,
}

/// Error returned by safe Windows certificate-store wrappers.
#[derive(Debug)]
pub enum CertificateStoreError {
    /// A crypt32 call failed.
    Windows {
        operation: &'static str,
        source: WindowsError,
    },
    /// A native integer could not be represented by a Rust type.
    NumericConversion { operation: &'static str },
}

/// Owned Windows certificate store handle.
#[repr(transparent)]
pub struct CertificateStore {
    inner: HCERTSTORE,
}

/// Owned Windows certificate context returned by store enumeration.
#[repr(transparent)]
pub struct CertificateContext {
    inner: NonNull<CERT_CONTEXT>,
}

impl CertificateStore {
    /// Opens a Windows system certificate store.
    pub fn open_system(
        name: SystemStoreName,
        location: SystemStoreLocation,
    ) -> Result<Self, CertificateStoreError> {
        Ok(Self {
            inner: {
                // SAFETY: `CERT_STORE_PROV_SYSTEM_W` selects a system store
                // provider and `name.as_wide()` is a NUL-terminated UTF-16
                // string that lives for this call. Windows returns an owned
                // store handle on success.
                unsafe {
                    CertOpenStore(
                        CERT_STORE_PROV_SYSTEM_W,
                        CERT_QUERY_ENCODING_TYPE::default(),
                        None,
                        CERT_OPEN_STORE_FLAGS(system_store_flag(location)),
                        Some(name.as_wide().as_ptr().cast::<c_void>()),
                    )
                }
            }
            .map_err(|source| windows_error("CertOpenStore", source))?,
        })
    }

    /// Adds an encoded certificate to this store.
    pub fn add_encoded_certificate(
        &self,
        encoding: CertificateEncoding,
        certificate_der: &[u8],
        disposition: AddDisposition,
    ) -> Result<(), CertificateStoreError> {
        // SAFETY: The store handle is valid for this call and `certificate_der`
        // is immutable memory. Crypt32 copies the encoded certificate into the
        // store before returning.
        unsafe {
            CertAddEncodedCertificateToStore(
                Some(self.inner),
                encoding.as_native(),
                certificate_der,
                disposition.as_native(),
                None,
            )
        }
        .map_err(|source| windows_error("CertAddEncodedCertificateToStore", source))
    }

    /// Finds one certificate context whose encoded bytes match `predicate`.
    ///
    /// The predicate receives DER bytes borrowed from each enumerated native
    /// certificate context for the duration of the call. The returned context is
    /// owned by the caller and must be deleted or dropped.
    pub fn find_certificate<P>(
        &self,
        mut predicate: P,
    ) -> Result<Option<CertificateContext>, CertificateStoreError>
    where
        P: FnMut(&[u8]) -> bool,
    {
        let mut previous: Option<CertificateContext> = None;
        loop {
            // SAFETY: The store handle is valid. `previous`, when present, is a
            // context returned by the previous `CertEnumCertificatesInStore`
            // call for this store. Windows releases the previous context when
            // advancing enumeration, so the Rust owner was consumed with
            // `into_raw` before passing the raw pointer.
            let Some(next) = NonNull::new(unsafe {
                CertEnumCertificatesInStore(
                    self.inner,
                    previous
                        .take()
                        .map(|context| context.into_raw().cast_const()),
                )
            }) else {
                return Ok(None);
            };

            // SAFETY: `next` is an owned, live certificate context returned by
            // the immediately preceding `CertEnumCertificatesInStore` call.
            let context = unsafe { CertificateContext::from_raw(next) };
            if predicate(context.encoded_certificate()?) {
                return Ok(Some(context));
            }

            previous = Some(context);
        }
    }
}

impl Drop for CertificateStore {
    fn drop(&mut self) {
        // SAFETY: `inner` is an owned store handle returned by `CertOpenStore`.
        let _closed = unsafe { CertCloseStore(Some(self.inner), 0) };
    }
}

impl CertificateContext {
    /// Creates an owned certificate context from a raw crypt32 context pointer.
    ///
    /// # Safety
    ///
    /// `inner` must be an owned, live `CERT_CONTEXT` returned by crypt32. It
    /// must not have been freed or consumed by `CertDeleteCertificateFromStore`.
    pub const unsafe fn from_raw(inner: NonNull<CERT_CONTEXT>) -> Self {
        Self { inner }
    }

    /// Returns the underlying raw crypt32 certificate context pointer.
    #[must_use]
    pub const fn as_raw(&self) -> *mut CERT_CONTEXT {
        self.inner.as_ptr()
    }

    /// Converts this owned context into a raw crypt32 context pointer.
    ///
    /// The caller becomes responsible for passing the pointer to a crypt32 API
    /// that consumes or frees it.
    #[must_use]
    pub const fn into_raw(self) -> *mut CERT_CONTEXT {
        let pointer = self.as_raw();
        mem::forget(self);
        pointer
    }

    /// Deletes this certificate from its store.
    pub fn delete(self) -> Result<(), CertificateStoreError> {
        // SAFETY: The pointer is an owned certificate context returned by store
        // enumeration. `CertDeleteCertificateFromStore` consumes and frees the
        // context, so ownership was transferred with `into_raw` first.
        unsafe { CertDeleteCertificateFromStore(self.into_raw()) }
            .map_err(|source| windows_error("CertDeleteCertificateFromStore", source))
    }

    fn encoded_certificate(&self) -> Result<&[u8], CertificateStoreError> {
        // SAFETY: `inner` is a non-null certificate context returned by crypt32.
        let context = unsafe { self.inner.as_ref() };
        let len = usize::try_from(context.cbCertEncoded).map_err(|_error| {
            CertificateStoreError::NumericConversion {
                operation: "read encoded certificate length",
            }
        })?;
        // SAFETY: `pbCertEncoded` and `cbCertEncoded` are owned by this live
        // certificate context. The returned slice is tied to `&self`, so it
        // cannot outlive the context.
        Ok(unsafe { slice::from_raw_parts(context.pbCertEncoded.cast_const(), len) })
    }
}

impl Drop for CertificateContext {
    fn drop(&mut self) {
        // SAFETY: `inner` is an owned certificate context returned by crypt32.
        let _freed = unsafe { CertFreeCertificateContext(Some(self.as_raw())) };
    }
}

impl SystemStoreName {
    const fn as_wide(self) -> &'static [u16] {
        match self {
            Self::Root => ROOT_STORE_NAME,
        }
    }
}

impl CertificateEncoding {
    const fn as_native(self) -> CERT_QUERY_ENCODING_TYPE {
        match self {
            Self::X509OrPkcs7 => {
                CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0)
            }
        }
    }
}

impl AddDisposition {
    const fn as_native(self) -> u32 {
        match self {
            Self::ReplaceExisting => CERT_STORE_ADD_REPLACE_EXISTING,
        }
    }
}

impl fmt::Display for CertificateStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows { operation, source } => {
                write!(
                    formatter,
                    "Windows certificate store call {operation} failed: {source}"
                )
            }
            Self::NumericConversion { operation } => {
                write!(
                    formatter,
                    "Windows certificate store numeric conversion failed during {operation}"
                )
            }
        }
    }
}

impl std::error::Error for CertificateStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Windows { source, .. } => Some(source),
            Self::NumericConversion { .. } => None,
        }
    }
}

const fn system_store_flag(location: SystemStoreLocation) -> u32 {
    match location {
        SystemStoreLocation::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
        SystemStoreLocation::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
    }
}

const fn windows_error(operation: &'static str, source: WindowsError) -> CertificateStoreError {
    CertificateStoreError::Windows { operation, source }
}
