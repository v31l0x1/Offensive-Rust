use std::{mem::zeroed, os::raw::c_void, ptr::null_mut};

use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError, LUID},
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
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

fn main() {
    if enable_privilege("SeDebugPrivilege") {
        println!("[+] SeDebugPrivilege enabled successfully.");
    } else {
        println!("[-] Failed to enable SeDebugPrivilege.");
    }

    // list_privileges();
}
