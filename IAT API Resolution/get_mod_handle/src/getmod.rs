use std::arch::asm;
use std::os::{raw::c_void, windows::raw::HANDLE};
use std::ptr::null_mut;

#[repr(C)]
#[allow(non_snake_case)]
struct LIST_ENTRY {
    Flink: *mut LIST_ENTRY,
    Blink: *mut LIST_ENTRY,
}

type PWSTR = *mut u16;
pub type PVOID = *mut c_void;
pub type PPVOID = *mut PVOID;
pub type BOOLEAN = u8;
pub type ULONG = u32;
pub type BYTE = u8;
#[allow(non_camel_case_types)]
pub type LARGE_INTEGER = i64;

#[repr(C)]
#[allow(non_snake_case)]
struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: PWSTR,
}

#[repr(C)]
#[allow(non_snake_case)]
struct PEB_LDR_DATA {
    Length: u32,
    Initialized: u8,
    SsHandle: *mut std::ffi::c_void,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
#[allow(non_snake_case)]
struct RTL_USER_PROCESS_PARAMETERS {
    Reserved1: [u8; 16],
    Reserved2: [*mut c_void; 10],
    ImagePathName: UNICODE_STRING,
    CommandLine: UNICODE_STRING,
}

#[repr(C)]
#[allow(non_snake_case)]
struct PEB_FREE_BLOCK {
    Next: *mut PEB_FREE_BLOCK,
    Size: ULONG,
}

#[repr(C)]
#[allow(non_snake_case)]
pub union LDR_DATA_TABLE_ENTRY_0 {
    pub CheckSum: u32,
    pub Reserved6: *mut c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
struct LDR_DATA_TABLE_ENTRY {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: PVOID,
    EntryPoint: PVOID,
    SizeOfImage: ULONG,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Flags: ULONG,
    LoadCount: u16,
    TlsIndex: u16,
    HashLinks: LIST_ENTRY,
    TimeDateStamp: u32,
}

type PPEBLOCKROUTINE = Option<unsafe extern "system" fn(*mut c_void)>;

#[repr(C)]
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct PEB {
    InheritedAddressSpace: BOOLEAN,
    ReadImageFileExecOptions: BOOLEAN,
    BeingDebugged: BOOLEAN,
    Spare: BOOLEAN,
    Mutant: HANDLE,
    ImageBaseAddress: PVOID,
    LoaderData: *mut PEB_LDR_DATA,
    ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    SubSystemData: PVOID,
    ProcessHeap: PVOID,
    FastPebLock: PVOID,
    FastPebLockRoutine: PPEBLOCKROUTINE,
    FastPebUnlockRoutine: PPEBLOCKROUTINE,
    EnvironmentUpdateCount: ULONG,
    KernelCallbackTable: PPVOID,
    EventLogSection: PVOID,
    EventLog: PVOID,
    FreeList: *mut PEB_FREE_BLOCK,
    TlsExpansionCounter: ULONG,
    TlsBitmap: PVOID,
    TlsBitmapBits: [ULONG; 2],
    ReadOnlySharedMemoryBase: PVOID,
    ReadOnlySharedMemoryHeap: PVOID,
    ReadOnlyStaticServerData: PPVOID,
    AnsiCodePageData: PVOID,
    OemCodePageData: PVOID,
    UnicodeCaseTableData: PVOID,
    NumberOfProcessors: ULONG,
    NtGlobalFlag: ULONG,
    Spare2: [BYTE; 4],
    CriticalSectionTimeout: LARGE_INTEGER,
    HeapSegmentReserve: ULONG,
    HeapSegmentCommit: ULONG,
    HeapDeCommitTotalFreeThreshold: ULONG,
    HeapDeCommitFreeBlockThreshold: ULONG,
    NumberOfHeaps: ULONG,
    MaximumNumberOfHeaps: ULONG,
    ProcessHeaps: PPVOID,
    GdiSharedHandleTable: PVOID,
    ProcessStarterHelper: PVOID,
    GdiDCAttributeList: PVOID,
    LoaderLock: PVOID,
    OSMajorVersion: ULONG,
    OSMinorVersion: ULONG,
    OSBuildNumber: ULONG,
    OSPlatformId: ULONG,
    ImageSubSystem: ULONG,
    ImageSubSystemMajorVersion: ULONG,
    ImageSubSystemMinorVersion: ULONG,
    GdiHandleBuffer: [ULONG; 0x22], // 34 elements
    PostProcessInitRoutine: ULONG,
    TlsExpansionBitmap: ULONG,
    TlsExpansionBitmapBits: [BYTE; 0x80], // 128 bytes
    SessionId: ULONG,
}

unsafe fn get_peb() -> *mut PEB {
    let peb: *mut PEB;
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            asm!(
                "mov {}, gs:[0x60]",
                out(reg) peb,
                options(nostack, preserves_flags)
            );
        }
    }
    #[cfg(target_arch = "x86")]
    {
        unsafe {
            asm!(
                "mov {}, fs:[0x30]",
                out(reg) peb,
                options(nostack, preserves_flags)
            );
        }
    }
    peb
}

/*

PEB -> PEB_LDR_DATA -> InLoadOrderModuleList -> LDR_DATA_TABLE_ENTRY -> BaseDllName

This variant used InLoadOrderModuleList to traverse the list of loaded modules in the process. It compares the
BaseDllName of each module with the provided mod_name and returns the DllBase address if a match is found.

*/

pub fn get_mod(mod_name: &str) -> PVOID {
    let peb = unsafe { get_peb() };
    if peb.is_null() {
        println!("Failed to get PEB address");
        return null_mut();
    }
    println!("PEB address: 0x{:016x}", peb as u64);

    let ldr = unsafe { (*peb).LoaderData };
    if ldr.is_null() {
        println!("Failed to get PEB_LDR_DATA address");
        return null_mut();
    }
    println!("PEB_LDR_DATA address: 0x{:016x}", ldr as u64);

    let head = unsafe { &(*ldr).InLoadOrderModuleList as *const LIST_ENTRY };
    let mut current = unsafe { (*head).Flink };

    while current != head as *mut LIST_ENTRY {
        let ldr_entry = current as *mut LDR_DATA_TABLE_ENTRY;
        let base_dll_name = unsafe { &(*ldr_entry).BaseDllName };
        let dll_name = unsafe {
            std::slice::from_raw_parts(base_dll_name.Buffer, (base_dll_name.Length / 2) as usize)
        };
        let dll_name_str = String::from_utf16_lossy(dll_name);

        if dll_name_str.eq_ignore_ascii_case(mod_name) {
            println!("Found module: {}", dll_name_str);
            return unsafe { (*ldr_entry).DllBase };
        }

        current = unsafe { (*current).Flink };
    }

    null_mut()
}

/*

PEB -> PEB_LDR_DATA -> InMemoryOrderModuleList -> LDR_DATA_TABLE_ENTRY -> FullDllName

This variant used InMemoryOrderModuleList to traverse the list of loaded modules in the process. It compares the
FullDllName of each module with the provided mod_name and returns the DllBase address if a match is found.

*/

// pub unsafe fn get_mod(mod_name: &str) -> PVOID {
//     let peb = get_peb();
//     if peb.is_null() {
//         println!("Failed to get PEB address");
//         return null_mut();
//     }
//     println!("PEB address: 0x{:016x}", peb as u64);

//     let ldr = (*peb).LoaderData;
//     if ldr.is_null() {
//         println!("Failed to get PEB_LDR_DATA address");
//         return null_mut();
//     }
//     println!("PEB_LDR_DATA address: 0x{:016x}", ldr as u64);

//     let head = &(*ldr).InMemoryOrderModuleList as *const LIST_ENTRY;
//     let mut current = (*head).Flink;

//     while current != head as *mut LIST_ENTRY {
//         let ldr_entry = current as *mut LDR_DATA_TABLE_ENTRY;
//         let base_dll_name = &(*ldr_entry).FullDllName;
//         let dll_name =
//             std::slice::from_raw_parts(base_dll_name.Buffer, (base_dll_name.Length / 2) as usize);
//         let dll_name_str = String::from_utf16_lossy(dll_name);

//         if dll_name_str.eq_ignore_ascii_case(mod_name) {
//             println!("Found module: {}", dll_name_str);
//             return (*ldr_entry).InInitializationOrderLinks.Flink as PVOID;
//         }

//         current = (*current).Flink;
//     }

//     null_mut()
// }
