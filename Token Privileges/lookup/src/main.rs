use std::{env::consts, ffi::CStr, mem::zeroed, ptr::null_mut, u32};

use windows_sys::Win32::{
    Security::{
        Authorization::ConvertSidToStringSidA, GetSidSubAuthority, GetSidSubAuthorityCount,
        GetTokenInformation, LookupAccountSidA, LookupPrivilegeNameA, SE_PRIVILEGE_ENABLED,
        SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED, SE_PRIVILEGE_USED_FOR_ACCESS,
        SECURITY_MANDATORY_LABEL_AUTHORITY, SID_NAME_USE, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES,
        TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel, TokenPrivileges, TokenUser,
    },
    System::{
        SystemServices::{
            SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID,
            SECURITY_MANDATORY_SYSTEM_RID, SECURITY_MANDATORY_UNTRUSTED_RID,
        },
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
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
            "[+] Token SID: {}",
            std::ffi::CStr::from_ptr(sid_string as *const i8)
                .to_str()
                .unwrap_or("Invalid SID")
        );

        let name: Vec<u8> = vec![0; 256];
        let domain: Vec<u8> = vec![0; 256];
        let mut name_size = name.len() as u32;
        let mut domain_size = domain.len() as u32;
        let mut sid_type: SID_NAME_USE = zeroed();

        if LookupAccountSidA(
            null_mut(),
            token_user.User.Sid,
            name.as_ptr() as *mut u8,
            &mut name_size,
            domain.as_ptr() as *mut u8,
            &mut domain_size,
            &mut sid_type,
        ) == 0
        {
            println!("[-] Failed to lookup account SID");
            return;
        }

        println!(
            "[+] Current User: {}\\{}",
            CStr::from_ptr(domain.as_ptr() as *const i8)
                .to_str()
                .unwrap(),
            CStr::from_ptr(name.as_ptr() as *const i8).to_str().unwrap()
        );

        let mut size = 0;
        GetTokenInformation(token, TokenIntegrityLevel, null_mut(), 0, &mut size);

        if size == 0 {
            println!("[-] Failed to get integrity level size");
            return;
        }

        let mut buffer = vec![0u8; size as usize];
        if GetTokenInformation(
            token,
            TokenIntegrityLevel,
            buffer.as_mut_ptr() as *mut _,
            size,
            &mut size,
        ) == 0
        {
            println!("[-] Failed to get integrity level");
            return;
        }

        let token_mandator_level = &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL);

        let sub_authority_count = *GetSidSubAuthorityCount(token_mandator_level.Label.Sid);
        let integrity_level = *GetSidSubAuthority(
            token_mandator_level.Label.Sid,
            sub_authority_count.wrapping_sub(1) as u32,
        );

        let integrity_str = match integrity_level as i32 {
            SECURITY_MANDATORY_UNTRUSTED_RID => "Untrusted",
            SECURITY_MANDATORY_LOW_RID => "Low",
            SECURITY_MANDATORY_MEDIUM_RID => "Medium",
            SECURITY_MANDATORY_HIGH_RID => "High",
            SECURITY_MANDATORY_SYSTEM_RID => "System",
            _ => "Unknown",
        };

        println!("[+] Integrity Level: {}", integrity_str);

        let mut size = 0;
        GetTokenInformation(token, TokenPrivileges, null_mut(), 0, &mut size);

        let mut buffer = vec![0u8; size as usize];

        if GetTokenInformation(
            token,
            TokenPrivileges,
            buffer.as_mut_ptr() as _,
            size,
            &mut size,
        ) == 0
        {
            println!("[-] Failed to get token privileges.");
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
