use std::{ffi::CStr, mem::zeroed, os::raw::c_void, ptr::null_mut};

use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError, LUID},
        Security::{
            AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeNameA,
            LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT,
            SE_PRIVILEGE_REMOVED, SE_PRIVILEGE_USED_FOR_ACCESS, TOKEN_ADJUST_PRIVILEGES,
            TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrivileges,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
    core::PCSTR,
};

fn enable_privilege(privilege_name: &str) -> bool {
    unsafe {
        let mut token_handle: *mut c_void = null_mut();

        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        ) == 0
        {
            println!("[-] Failed to open process token.");
            return false;
        }

        let mut luid = zeroed::<LUID>();
        let privilege_name = std::ffi::CString::new(privilege_name).unwrap();
        if LookupPrivilegeValueA(
            null_mut(),
            PCSTR::from(privilege_name.as_ptr() as *const u8),
            &mut luid,
        ) == 0
        {
            println!("[-] Failed to lookup privilege value.");
            CloseHandle(token_handle);
            return false;
        }

        let mut token_privileges = zeroed::<TOKEN_PRIVILEGES>();
        token_privileges.PrivilegeCount = 1;
        token_privileges.Privileges[0].Luid = luid;
        token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if AdjustTokenPrivileges(
            token_handle,
            0,
            &mut token_privileges,
            size_of::<TOKEN_PRIVILEGES>() as u32,
            null_mut(),
            null_mut(),
        ) == 0
        {
            println!("[-] Failed to adjust token privileges.");
            CloseHandle(token_handle);
            return false;
        }

        let error = GetLastError();

        if error == ERROR_NOT_ALL_ASSIGNED {
            println!("[-] The token does not have the specified privilege.");
            CloseHandle(token_handle);
            return false;
        }

        CloseHandle(token_handle);
    }

    true
}

fn get_privielge_attribute(attributes: u32) -> String {
    if attributes & SE_PRIVILEGE_ENABLED != 0 {
        return "Enabled".to_string();
    } else if attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT != 0 {
        return "Enabled by default".to_string();
    } else if attributes & SE_PRIVILEGE_REMOVED != 0 {
        return "Removed".to_string();
    } else if attributes & SE_PRIVILEGE_USED_FOR_ACCESS != 0 {
        return "Used for access".to_string();
    }

    "Disabled".to_string()
}

fn list_privileges() {
    unsafe {
        let mut token_handle: *mut c_void = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
            println!("[-] Failed to open process token.");
            return;
        }

        let mut size = 0;
        GetTokenInformation(token_handle, TokenPrivileges, null_mut(), 0, &mut size);

        let mut buffer = vec![0u8; size as usize];
        if GetTokenInformation(
            token_handle,
            TokenPrivileges,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut size,
        ) == 0
        {
            println!("[-] Failed to get token information.");
            CloseHandle(token_handle);
            return;
        }

        let token_privileges = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
        let privileges_ptr = token_privileges.Privileges.as_ptr();

        println!("[+] Current token privileges:");
        for i in 0..token_privileges.PrivilegeCount as usize {
            let mut privilege_name = vec![0u8; 256];
            let mut size = privilege_name.len() as u32;

            let luid_ptr = &(*privileges_ptr.add(i)).Luid;

            LookupPrivilegeNameA(null_mut(), luid_ptr, privilege_name.as_mut_ptr(), &mut size);
            println!(
                "    {:30} {}",
                CStr::from_ptr(privilege_name.as_ptr() as *const i8)
                    .to_str()
                    .unwrap(),
                get_privielge_attribute((*privileges_ptr.add(i)).Attributes)
            )
        }
    }
}

fn main() {
    if enable_privilege("SeDebugPrivilege") {
        println!("[+] SeDebugPrivilege enabled successfully.");
    } else {
        println!("[-] Failed to enable SeDebugPrivilege.");
    }

    list_privileges();
}
