//! The `winx` module contains code specific to Windows, supported by the
//! `winx` crate.

pub(crate) mod fs;

// #[minwin]
// mod boop {}

#[allow(non_camel_case_types, non_snake_case)]
pub(crate) mod bindings {
    pub type WIN32_ERROR = u32;
    pub const ERROR_FILE_NOT_FOUND: WIN32_ERROR = 2;
    pub const ERROR_PATH_NOT_FOUND: WIN32_ERROR = 3;
    pub const ERROR_ACCESS_DENIED: WIN32_ERROR = 5;
    pub const ERROR_NOT_SUPPORTED: WIN32_ERROR = 50;
    pub const ERROR_FILE_EXISTS: WIN32_ERROR = 80;
    pub const ERROR_INVALID_PARAMETER: WIN32_ERROR = 87;
    pub const ERROR_INVALID_NAME: WIN32_ERROR = 123;
    pub const ERROR_ALREADY_EXISTS: WIN32_ERROR = 183;
    pub const ERROR_DIRECTORY: WIN32_ERROR = 267;
    pub const ERROR_DIRECTORY_NOT_SUPPORTED: WIN32_ERROR = 336;
    pub const ERROR_STOPPED_ON_SYMLINK: WIN32_ERROR = 681;
    pub const ERROR_TOO_MANY_LINKS: WIN32_ERROR = 1142;

    pub const SUCCESS: u32 = 0;
    pub const SECURITY_DYNAMIC_TRACKING: u8 = 1 as _;
    pub const SECURITY_STATIC_TRACKING: u8 = 0 as _;
    pub const OBJ_CASE_INSENSITIVE: i32 = 64;
    pub const OBJ_INHERIT: i32 = 2;

    pub type NTSTATUS = i32;
    pub const STATUS_OBJECT_NAME_COLLISION: i32 = -1073741771;
    pub const STATUS_PENDING: i32 = 259;
    pub const STATUS_SUCCESS: i32 = 0;

    pub type HANDLE = isize;
    pub const INVALID_HANDLE_VALUE: isize = -1;

    pub type FILE_ACCESS_RIGHTS = u32;
    pub const FILE_WRITE_DATA: FILE_ACCESS_RIGHTS = 2;
    pub const FILE_READ_ATTRIBUTES: FILE_ACCESS_RIGHTS = 128;
    pub const DELETE: FILE_ACCESS_RIGHTS = 65536;
    pub const SYNCHRONIZE: FILE_ACCESS_RIGHTS = 1048576;
    pub const FILE_GENERIC_READ: FILE_ACCESS_RIGHTS = 1179785;
    pub const FILE_GENERIC_WRITE: FILE_ACCESS_RIGHTS = 1179926;

    pub type FILE_CREATION_DISPOSITION = u32;
    pub const CREATE_NEW: FILE_CREATION_DISPOSITION = 1;
    pub const CREATE_ALWAYS: FILE_CREATION_DISPOSITION = 2;
    pub const OPEN_EXISTING: FILE_CREATION_DISPOSITION = 3;
    pub const OPEN_ALWAYS: FILE_CREATION_DISPOSITION = 4;
    pub const TRUNCATE_EXISTING: FILE_CREATION_DISPOSITION = 5;

    pub type GENERIC_ACCESS_RIGHTS = u32;
    pub const GENERIC_READ: GENERIC_ACCESS_RIGHTS = 2147483648;
    pub const GENERIC_WRITE: GENERIC_ACCESS_RIGHTS = 1073741824;
    pub const GENERIC_ALL: GENERIC_ACCESS_RIGHTS = 268435456;

    pub const FILE_OPENED: u32 = 1;
    pub const FILE_OPEN_REMOTE_INSTANCE: u32 = 1024;
    pub const FILE_OVERWRITTEN: u32 = 3;

    pub type BOOL = i32;
    #[repr(C)]
    pub struct SECURITY_ATTRIBUTES {
        pub nLength: u32,
        pub lpSecurityDescriptor: *mut std::ffi::c_void,
        pub bInheritHandle: BOOL,
    }

    pub type SECURITY_IMPERSONATION_LEVEL = i32;

    pub type BOOLEAN = u8;

    #[repr(C)]
    pub struct SECURITY_QUALITY_OF_SERVICE {
        pub Length: u32,
        pub ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
        pub ContextTrackingMode: u8,
        pub EffectiveOnly: BOOLEAN,
    }

    #[repr(C)]
    pub struct UNICODE_STRING {
        pub Length: u16,
        pub MaximumLength: u16,
        pub Buffer: *mut u16,
    }
    #[repr(C)]
    pub struct OBJECT_ATTRIBUTES {
        pub Length: u32,
        pub RootDirectory: HANDLE,
        pub ObjectName: *mut UNICODE_STRING,
        pub Attributes: u32,
        pub SecurityDescriptor: *mut std::ffi::c_void,
        pub SecurityQualityOfService: *mut std::ffi::c_void,
    }
    #[repr(C)]
    pub union IO_STATUS_BLOCK_0 {
        pub Status: NTSTATUS,
        pub Pointer: *mut std::ffi::c_void,
    }
    #[repr(C)]
    pub struct IO_STATUS_BLOCK {
        pub Anonymous: IO_STATUS_BLOCK_0,
        pub Information: usize,
    }

    pub type FILE_FLAGS_AND_ATTRIBUTES = u32;
    pub const FILE_ATTRIBUTE_READONLY: FILE_FLAGS_AND_ATTRIBUTES = 1;
    pub const FILE_ATTRIBUTE_HIDDEN: FILE_FLAGS_AND_ATTRIBUTES = 2;
    pub const FILE_ATTRIBUTE_SYSTEM: FILE_FLAGS_AND_ATTRIBUTES = 4;
    pub const FILE_ATTRIBUTE_DIRECTORY: FILE_FLAGS_AND_ATTRIBUTES = 16;
    pub const FILE_ATTRIBUTE_ARCHIVE: FILE_FLAGS_AND_ATTRIBUTES = 32;
    pub const FILE_ATTRIBUTE_DEVICE: FILE_FLAGS_AND_ATTRIBUTES = 64;
    pub const FILE_ATTRIBUTE_NORMAL: FILE_FLAGS_AND_ATTRIBUTES = 128;
    pub const FILE_ATTRIBUTE_TEMPORARY: FILE_FLAGS_AND_ATTRIBUTES = 256;
    pub const FILE_ATTRIBUTE_SPARSE_FILE: FILE_FLAGS_AND_ATTRIBUTES = 512;
    pub const FILE_ATTRIBUTE_REPARSE_POINT: FILE_FLAGS_AND_ATTRIBUTES = 1024;
    pub const FILE_ATTRIBUTE_COMPRESSED: FILE_FLAGS_AND_ATTRIBUTES = 2048;
    pub const FILE_ATTRIBUTE_OFFLINE: FILE_FLAGS_AND_ATTRIBUTES = 4096;
    pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: FILE_FLAGS_AND_ATTRIBUTES = 8192;
    pub const FILE_ATTRIBUTE_ENCRYPTED: FILE_FLAGS_AND_ATTRIBUTES = 16384;
    pub const FILE_ATTRIBUTE_INTEGRITY_STREAM: FILE_FLAGS_AND_ATTRIBUTES = 32768;
    pub const FILE_ATTRIBUTE_VIRTUAL: FILE_FLAGS_AND_ATTRIBUTES = 65536;
    pub const FILE_ATTRIBUTE_NO_SCRUB_DATA: FILE_FLAGS_AND_ATTRIBUTES = 131072;
    pub const FILE_ATTRIBUTE_EA: FILE_FLAGS_AND_ATTRIBUTES = 262144;
    pub const FILE_ATTRIBUTE_PINNED: FILE_FLAGS_AND_ATTRIBUTES = 524288;
    pub const FILE_ATTRIBUTE_UNPINNED: FILE_FLAGS_AND_ATTRIBUTES = 1048576;
    pub const FILE_ATTRIBUTE_RECALL_ON_OPEN: FILE_FLAGS_AND_ATTRIBUTES = 262144;
    pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: FILE_FLAGS_AND_ATTRIBUTES = 4194304;
    pub const FILE_FLAG_WRITE_THROUGH: FILE_FLAGS_AND_ATTRIBUTES = 2147483648;
    pub const FILE_FLAG_OVERLAPPED: FILE_FLAGS_AND_ATTRIBUTES = 1073741824;
    pub const FILE_FLAG_NO_BUFFERING: FILE_FLAGS_AND_ATTRIBUTES = 536870912;
    pub const FILE_FLAG_RANDOM_ACCESS: FILE_FLAGS_AND_ATTRIBUTES = 268435456;
    pub const FILE_FLAG_SEQUENTIAL_SCAN: FILE_FLAGS_AND_ATTRIBUTES = 134217728;
    pub const FILE_FLAG_DELETE_ON_CLOSE: FILE_FLAGS_AND_ATTRIBUTES = 67108864;
    pub const FILE_FLAG_BACKUP_SEMANTICS: FILE_FLAGS_AND_ATTRIBUTES = 33554432;
    pub const FILE_FLAG_POSIX_SEMANTICS: FILE_FLAGS_AND_ATTRIBUTES = 16777216;
    pub const FILE_FLAG_SESSION_AWARE: FILE_FLAGS_AND_ATTRIBUTES = 8388608;
    pub const FILE_FLAG_OPEN_REPARSE_POINT: FILE_FLAGS_AND_ATTRIBUTES = 2097152;
    pub const FILE_FLAG_OPEN_NO_RECALL: FILE_FLAGS_AND_ATTRIBUTES = 1048576;
    pub const SECURITY_IDENTIFICATION: FILE_FLAGS_AND_ATTRIBUTES = 65536;
    pub const SECURITY_IMPERSONATION: FILE_FLAGS_AND_ATTRIBUTES = 131072;
    pub const SECURITY_DELEGATION: FILE_FLAGS_AND_ATTRIBUTES = 196608;
    pub const SECURITY_CONTEXT_TRACKING: FILE_FLAGS_AND_ATTRIBUTES = 262144;
    pub const SECURITY_EFFECTIVE_ONLY: FILE_FLAGS_AND_ATTRIBUTES = 524288;
    pub const SECURITY_SQOS_PRESENT: FILE_FLAGS_AND_ATTRIBUTES = 1048576;

    pub type FILE_SHARE_MODE = u32;
    pub const FILE_SHARE_DELETE: FILE_SHARE_MODE = 4;
    pub const FILE_SHARE_READ: FILE_SHARE_MODE = 1;
    pub const FILE_SHARE_WRITE: FILE_SHARE_MODE = 2;

    pub type NTCREATEFILE_CREATE_DISPOSITION = u32;
    pub const FILE_CREATE: NTCREATEFILE_CREATE_DISPOSITION = 2;
    pub const FILE_OPEN: NTCREATEFILE_CREATE_DISPOSITION = 1;
    pub const FILE_OPEN_IF: NTCREATEFILE_CREATE_DISPOSITION = 3;
    pub const FILE_OVERWRITE: NTCREATEFILE_CREATE_DISPOSITION = 4;
    pub const FILE_OVERWRITE_IF: NTCREATEFILE_CREATE_DISPOSITION = 5;

    pub type NTCREATEFILE_CREATE_OPTIONS = u32;
    pub const FILE_NON_DIRECTORY_FILE: NTCREATEFILE_CREATE_OPTIONS = 64;
    pub const FILE_WRITE_THROUGH: NTCREATEFILE_CREATE_OPTIONS = 2;
    pub const FILE_SEQUENTIAL_ONLY: NTCREATEFILE_CREATE_OPTIONS = 4;
    pub const FILE_RANDOM_ACCESS: NTCREATEFILE_CREATE_OPTIONS = 2048;
    pub const FILE_NO_INTERMEDIATE_BUFFERING: NTCREATEFILE_CREATE_OPTIONS = 8;
    pub const FILE_SYNCHRONOUS_IO_NONALERT: NTCREATEFILE_CREATE_OPTIONS = 32;
    pub const FILE_OPEN_REPARSE_POINT: NTCREATEFILE_CREATE_OPTIONS = 2097152;
    pub const FILE_DELETE_ON_CLOSE: NTCREATEFILE_CREATE_OPTIONS = 4096;
    pub const FILE_OPEN_FOR_BACKUP_INTENT: NTCREATEFILE_CREATE_OPTIONS = 16384;
    pub const FILE_OPEN_NO_RECALL: NTCREATEFILE_CREATE_OPTIONS = 4194304;

    #[link(name = "kernel32", kind = "raw-dylib")]
    extern "system" {
        pub fn SetLastError(dwErrCode: WIN32_ERROR);
        pub fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: FILE_SHARE_MODE,
            lpSecurityAttributes: *const SECURITY_ATTRIBUTES,
            dwCreationDisposition: FILE_CREATION_DISPOSITION,
            dwFlagsAndAttributes: FILE_FLAGS_AND_ATTRIBUTES,
            hTemplateFile: HANDLE,
        ) -> HANDLE;
    }
    #[link(name = "ntdll", kind = "raw-dylib")]
    extern "system" {
        pub fn RtlNtStatusToDosError(Status: NTSTATUS) -> u32;
        pub fn NtCreateFile(
            FileHandle: *mut HANDLE,
            DesiredAccess: FILE_ACCESS_RIGHTS,
            ObjectAttributes: *const OBJECT_ATTRIBUTES,
            IoStatusBlock: *mut IO_STATUS_BLOCK,
            AllocationSize: *const i64,
            FileAttributes: FILE_FLAGS_AND_ATTRIBUTES,
            ShareAccess: FILE_SHARE_MODE,
            CreateDisposition: NTCREATEFILE_CREATE_DISPOSITION,
            CreateOptions: NTCREATEFILE_CREATE_OPTIONS,
            EaBuffer: *const std::ffi::c_void,
            EaLength: u32,
        ) -> NTSTATUS;
    }
}
