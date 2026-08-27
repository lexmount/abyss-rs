#pragma once

/*
 * Shared ABI between the Abyss Windows service and the thin WFP callout driver.
 *
 * The driver deliberately exposes only a tiny control surface: configure the
 * local proxy process/port. Product policy, TLS MITM, provider parsing, and
 * audit logic stay in Rust user-mode code.
 */

#ifdef ABYSS_CALLOUT_BINDGEN
#include <stdint.h>

/*
 * bindgen only needs the stable ABI surface below, not the full Windows SDK.
 * These definitions mirror the Windows integer widths and CTL_CODE inputs so
 * Rust bindings can be generated from this header without pulling in thousands
 * of unrelated SDK declarations.
 */
typedef uint32_t ULONG;
typedef uint16_t USHORT;
typedef uint8_t UCHAR;
typedef struct _GUID {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} GUID;

#define FILE_DEVICE_NETWORK ((uint32_t)0x00000012)
#define METHOD_BUFFERED ((uint32_t)0)
#define FILE_WRITE_DATA ((uint32_t)0x0002)
#define CTL_CODE(DeviceType, Function, Method, Access)                                                                 \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#elif defined(_KERNEL_MODE)
#include <ntddk.h>
#else
#include <Windows.h>
#include <winioctl.h>
#endif

/*
 * Stable names shared by the installer, kernel driver, and Rust service.
 *
 * The kernel creates ABYSS_CALLOUT_NT_DEVICE_NAME and links it through
 * ABYSS_CALLOUT_DOS_DEVICE_NAME. User-mode code opens the Win32 path with
 * CreateFileW before sending DeviceIoControl requests.
 */
#define ABYSS_CALLOUT_SERVICE_NAME L"AbyssWfpCallout"
#define ABYSS_CALLOUT_NT_DEVICE_NAME L"\\Device\\AbyssWfpCallout"
#define ABYSS_CALLOUT_DOS_DEVICE_NAME L"\\DosDevices\\AbyssWfpCallout"
#define ABYSS_CALLOUT_WIN32_DEVICE_NAME L"\\\\.\\AbyssWfpCallout"

/*
 * IOCTL namespace for the device control ABI.
 *
 * The configure IOCTL uses METHOD_BUFFERED so the driver receives a validated
 * system buffer. CONFIGURE copies an ABYSS_CALLOUT_REDIRECT_CONFIG from user
 * mode into the driver state.
 */
#define ABYSS_CALLOUT_IOCTL_INDEX 0xA00
#define ABYSS_CALLOUT_IOCTL_CONFIGURE                                                                                  \
    CTL_CODE(FILE_DEVICE_NETWORK, ABYSS_CALLOUT_IOCTL_INDEX + 1, METHOD_BUFFERED, FILE_WRITE_DATA)
#ifdef ABYSS_CALLOUT_BINDGEN
static const uint32_t ABYSS_CALLOUT_IOCTL_CONFIGURE_BINDGEN = ABYSS_CALLOUT_IOCTL_CONFIGURE;
#endif

/*
 * WFP object identifiers used by both sides of the adapter.
 *
 * The driver registers the callout keys below. The Rust service installs
 * FWPM_FILTER0 objects that reference those same callout keys when a configured
 * intercept rule should invoke the driver.
 */
#define ABYSS_GUID_DATA4_BYTE(Data4Value, ByteIndex) (UCHAR)(((Data4Value) >> (56 - (8 * (ByteIndex)))) & 0xffu)

#define ABYSS_GUID_INIT(Data1Value, Data2Value, Data3Value, Data4Value)                                                \
    {                                                                                                                  \
        (Data1Value), (Data2Value), (Data3Value),                                                                      \
        {                                                                                                              \
            ABYSS_GUID_DATA4_BYTE((Data4Value), 0), ABYSS_GUID_DATA4_BYTE((Data4Value), 1),                            \
                ABYSS_GUID_DATA4_BYTE((Data4Value), 2), ABYSS_GUID_DATA4_BYTE((Data4Value), 3),                        \
                ABYSS_GUID_DATA4_BYTE((Data4Value), 4), ABYSS_GUID_DATA4_BYTE((Data4Value), 5),                        \
                ABYSS_GUID_DATA4_BYTE((Data4Value), 6), ABYSS_GUID_DATA4_BYTE((Data4Value), 7),                        \
        }                                                                                                              \
    }

#define ABYSS_WFP_PROVIDER_KEY_DATA1 0x6f7f3e63u
#define ABYSS_WFP_PROVIDER_KEY_DATA2 0x0536u
#define ABYSS_WFP_PROVIDER_KEY_DATA3 0x545au
#define ABYSS_WFP_PROVIDER_KEY_DATA4 0x9f2d2e2b8e7a0f0dULL

#define ABYSS_WFP_SUBLAYER_KEY_DATA1 0x8e7f8f70u
#define ABYSS_WFP_SUBLAYER_KEY_DATA2 0x299cu
#define ABYSS_WFP_SUBLAYER_KEY_DATA3 0x5a17u
#define ABYSS_WFP_SUBLAYER_KEY_DATA4 0x97b13d1dc7dc188eULL

#define ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA1 0x4b2a8f72u
#define ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA2 0x13f5u
#define ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA3 0x5bb4u
#define ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4 0xae438f3e4fe97c41ULL

#define ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA1 0xc4a61c7bu
#define ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA2 0x0fb7u
#define ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA3 0x5dc4u
#define ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4 0xb1bf0e48a1a8fb62ULL

#define ABYSS_WFP_PROVIDER_KEY_INIT                                                                                    \
    ABYSS_GUID_INIT(ABYSS_WFP_PROVIDER_KEY_DATA1, ABYSS_WFP_PROVIDER_KEY_DATA2, ABYSS_WFP_PROVIDER_KEY_DATA3,          \
                    ABYSS_WFP_PROVIDER_KEY_DATA4)
#define ABYSS_WFP_SUBLAYER_KEY_INIT                                                                                    \
    ABYSS_GUID_INIT(ABYSS_WFP_SUBLAYER_KEY_DATA1, ABYSS_WFP_SUBLAYER_KEY_DATA2, ABYSS_WFP_SUBLAYER_KEY_DATA3,          \
                    ABYSS_WFP_SUBLAYER_KEY_DATA4)
#define ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_INIT                                                                     \
    ABYSS_GUID_INIT(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA1, ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA2,          \
                    ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA3, ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4)
#define ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_INIT                                                                     \
    ABYSS_GUID_INIT(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA1, ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA2,          \
                    ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA3, ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4)

#ifdef ABYSS_CALLOUT_BINDGEN
static const uint32_t ABYSS_WFP_PROVIDER_KEY_DATA1_BINDGEN = ABYSS_WFP_PROVIDER_KEY_DATA1;
static const uint16_t ABYSS_WFP_PROVIDER_KEY_DATA2_BINDGEN = ABYSS_WFP_PROVIDER_KEY_DATA2;
static const uint16_t ABYSS_WFP_PROVIDER_KEY_DATA3_BINDGEN = ABYSS_WFP_PROVIDER_KEY_DATA3;
static const uint8_t ABYSS_WFP_PROVIDER_KEY_DATA4_0_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_PROVIDER_KEY_DATA4, 0);
static const uint8_t ABYSS_WFP_PROVIDER_KEY_DATA4_1_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_PROVIDER_KEY_DATA4, 1);
static const uint8_t ABYSS_WFP_PROVIDER_KEY_DATA4_2_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_PROVIDER_KEY_DATA4, 2);
static const uint8_t ABYSS_WFP_PROVIDER_KEY_DATA4_3_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_PROVIDER_KEY_DATA4, 3);
static const uint8_t ABYSS_WFP_PROVIDER_KEY_DATA4_4_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_PROVIDER_KEY_DATA4, 4);
static const uint8_t ABYSS_WFP_PROVIDER_KEY_DATA4_5_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_PROVIDER_KEY_DATA4, 5);
static const uint8_t ABYSS_WFP_PROVIDER_KEY_DATA4_6_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_PROVIDER_KEY_DATA4, 6);
static const uint8_t ABYSS_WFP_PROVIDER_KEY_DATA4_7_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_PROVIDER_KEY_DATA4, 7);

static const uint32_t ABYSS_WFP_SUBLAYER_KEY_DATA1_BINDGEN = ABYSS_WFP_SUBLAYER_KEY_DATA1;
static const uint16_t ABYSS_WFP_SUBLAYER_KEY_DATA2_BINDGEN = ABYSS_WFP_SUBLAYER_KEY_DATA2;
static const uint16_t ABYSS_WFP_SUBLAYER_KEY_DATA3_BINDGEN = ABYSS_WFP_SUBLAYER_KEY_DATA3;
static const uint8_t ABYSS_WFP_SUBLAYER_KEY_DATA4_0_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_SUBLAYER_KEY_DATA4, 0);
static const uint8_t ABYSS_WFP_SUBLAYER_KEY_DATA4_1_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_SUBLAYER_KEY_DATA4, 1);
static const uint8_t ABYSS_WFP_SUBLAYER_KEY_DATA4_2_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_SUBLAYER_KEY_DATA4, 2);
static const uint8_t ABYSS_WFP_SUBLAYER_KEY_DATA4_3_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_SUBLAYER_KEY_DATA4, 3);
static const uint8_t ABYSS_WFP_SUBLAYER_KEY_DATA4_4_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_SUBLAYER_KEY_DATA4, 4);
static const uint8_t ABYSS_WFP_SUBLAYER_KEY_DATA4_5_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_SUBLAYER_KEY_DATA4, 5);
static const uint8_t ABYSS_WFP_SUBLAYER_KEY_DATA4_6_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_SUBLAYER_KEY_DATA4, 6);
static const uint8_t ABYSS_WFP_SUBLAYER_KEY_DATA4_7_BINDGEN = ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_SUBLAYER_KEY_DATA4, 7);

static const uint32_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA1_BINDGEN = ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA1;
static const uint16_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA2_BINDGEN = ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA2;
static const uint16_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA3_BINDGEN = ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA3;
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4_0_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4, 0);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4_1_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4, 1);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4_2_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4, 2);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4_3_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4, 3);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4_4_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4, 4);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4_5_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4, 5);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4_6_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4, 6);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4_7_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4_DATA4, 7);

static const uint32_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA1_BINDGEN = ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA1;
static const uint16_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA2_BINDGEN = ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA2;
static const uint16_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA3_BINDGEN = ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA3;
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4_0_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4, 0);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4_1_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4, 1);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4_2_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4, 2);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4_3_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4, 3);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4_4_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4, 4);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4_5_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4, 5);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4_6_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4, 6);
static const uint8_t ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4_7_BINDGEN =
    ABYSS_GUID_DATA4_BYTE(ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6_DATA4, 7);
#endif

/*
 * Runtime redirect configuration.
 *
 * Direction:
 *   - CONFIGURE: user-mode service -> kernel driver.
 *
 * Size must be set to sizeof(ABYSS_CALLOUT_REDIRECT_CONFIG). Reserved fields
 * must be zero and are kept for future ABI-compatible extension.
 */
typedef struct _ABYSS_CALLOUT_REDIRECT_CONFIG {
    /* ABI size/version guard for forward-compatible validation. */
    ULONG Size;
    /* Nonzero enables connect redirection; zero makes the callout permit. */
    ULONG Enabled;
    /* PID of the local Rust proxy process to avoid redirecting proxy egress. */
    ULONG ProxyProcessId;
    /* Loopback TCP port in host byte order. */
    USHORT ProxyPort;
    /* Reserved for future use; callers must set this to zero. */
    USHORT Reserved;
    /* Reserved for future use; callers must set this to zero. */
    ULONG Reserved2;
} ABYSS_CALLOUT_REDIRECT_CONFIG, *PABYSS_CALLOUT_REDIRECT_CONFIG;

/*
 * Redirect metadata attached to each redirected TCP connect request.
 *
 * Direction:
 *   kernel driver -> WFP redirect context -> user-mode service.
 *
 * The driver writes this structure into FWPS_CONNECT_REQUEST0::localRedirectContext
 * before changing the remote address to loopback. The Rust proxy later recovers
 * it from the accepted socket with SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT.
 *
 * ABYSS_CALLOUT_REDIRECT_CONTEXT is the complete fixed header. When Size is
 * larger than sizeof(ABYSS_CALLOUT_REDIRECT_CONTEXT), the remaining bytes
 * immediately following the header contain the WFP ALE_APP_ID in UTF-16LE.
 */
#define ABYSS_CALLOUT_MAX_APPLICATION_ID_BYTES 4096u
#ifdef ABYSS_CALLOUT_BINDGEN
static const uint32_t ABYSS_CALLOUT_MAX_APPLICATION_ID_BYTES_BINDGEN = ABYSS_CALLOUT_MAX_APPLICATION_ID_BYTES;
#endif

typedef struct _ABYSS_CALLOUT_REDIRECT_CONTEXT {
    /* Total context size, including the trailing application identifier. */
    ULONG Size;
    /* AF_INET or AF_INET6. */
    ULONG AddressFamily;
    /* Original remote TCP port in host byte order. */
    USHORT OriginalPort;
    /* Reserved for future use; currently zero. */
    USHORT Reserved;
    union {
        /* Original IPv4 address in network byte order, matching SOCKADDR_IN. */
        ULONG Ipv4Address;
        /* Original IPv6 address bytes, matching SOCKADDR_IN6. */
        UCHAR Ipv6Address[16];
    } OriginalDestination;
    /* Source process ID, or zero when WFP did not supply one. */
    ULONG ProcessId;
} ABYSS_CALLOUT_REDIRECT_CONTEXT, *PABYSS_CALLOUT_REDIRECT_CONTEXT;

#ifdef __cplusplus
extern "C" {
#endif

extern const GUID ABYSS_WFP_PROVIDER_KEY;
extern const GUID ABYSS_WFP_SUBLAYER_KEY;
extern const GUID ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V4;
extern const GUID ABYSS_WFP_CALLOUT_CONNECT_REDIRECT_V6;

#ifdef __cplusplus
}
#endif
