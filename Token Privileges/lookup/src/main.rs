use std::{mem::zeroed, ptr::null_mut};

use windows_sys::Win32::{
    Security::{
        Authorization::ConvertSidToStringSidA, GetTokenInformation, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

fn main() {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            println!("[-] Failed to open process token");
            return;
        }

        let mut size = 0;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut size);

        if size == 0 {
            println!("[-] Failed to get token information size");
            return;
        }

        let mut buffer = vec![0u8; size as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr() as *mut _,
            size,
            &mut size,
        ) == 0
        {
            println!("[-] Failed to get token information");
            return;
        }

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);

        let mut sid_string = null_mut();
        if ConvertSidToStringSidA(token_user.User.Sid, &mut sid_string) == 0 {
            println!("[-] Failed to convert SID to string");
            return;
        }

        println!(
            "Token SID: {}",
            std::ffi::CStr::from_ptr(sid_string as *const i8)
                .to_str()
                .unwrap_or("Invalid SID")
        );
    }
}
