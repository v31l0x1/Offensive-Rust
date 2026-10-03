use std::{mem::zeroed, ptr::null_mut};

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        DataExchange::{
            APPCLASS_STANDARD, APPCMD_FILTERINITS, CONVINFO, CP_WINANSI, DMLERR_NO_ERROR,
            DdeConnectList, DdeDisconnectList, DdeGetLastError, DdeInitializeA, DdeQueryConvInfo,
            DdeQueryNextServer, DdeQueryStringA, HCONV, HSZ, QID_SYNC,
        },
        Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameA},
    },
    UI::WindowsAndMessaging::GetWindowThreadProcessId,
};

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

fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() < 2 {
        println!("Usage: {} <command>", args[0]);
        println!("Commands:");
        println!("  enum_dde - Enumerate DDE servers");
        return;
    }

    match args[1].as_str() {
        "enum_dde" => enum_dde(),
        _ => {
            println!("Unknown command: {}", args[1]);
            println!("Usage: {} <command>", args[0]);
            println!("Commands:");
            println!("  enum_dde - Enumerate DDE servers");
        }
    }
}
