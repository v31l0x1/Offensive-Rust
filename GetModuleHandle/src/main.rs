use core::arch::asm;
use std::{os::raw::c_void, ptr::null_mut};

unsafe fn read_gs_qword(offset: u64) -> u64 {
    let out: u64;
    unsafe {
        asm!(
            "mov {out}, qword ptr gs:[{offset}]",
            out = out(reg) out,
            offset = in(reg) offset,
            options(nostack, preserves_flags, readonly)
        );
    }
    out
}

fn get_module_handle(module: &str) -> *mut c_void {
    unsafe {

        // dt nt!_PEB (0x60)
        let peb = read_gs_qword(0x60) as *const u8;
        if peb.is_null() {
            return null_mut();
        }


        // dt nt!_PEB_LDR_DATA (0x60 + 0x18)

        let ldr = *(peb.add(0x18) as *const *const u8);
        if ldr.is_null() {
            return null_mut();
        }

        // dt nt!_LDR_DATA_TABLE_ENTRY (0x60 + 0x18 + 0x20) => InMemoryOrderLinks

        let list_head = ldr.add(0x20);
        let mut current = *(list_head as *const *const u8);

        while !current.is_null() && current != list_head {

            // InLoadOrderModuleList is 0x10 bytes in LDR_DATA_TABLE_ENTRY
            let entry = current.sub(0x10);
            
            let dll_name_len = *(entry.add(0x58) as *const u16) as usize / 2;
            let base_dll_name = *(entry.add(0x60) as *const *const u16);

            if !base_dll_name.is_null() && dll_name_len != 0 {
                let dll_name_slice = std::slice::from_raw_parts(base_dll_name, dll_name_len);
                let dll_name = String::from_utf16_lossy(dll_name_slice);

                // println!("[+] DllName: {}", dll_name);

                if dll_name.eq_ignore_ascii_case(module) {
                    let dll_base =  *(entry.add(0x30) as *const *mut c_void);
                    println!("[+] DllName: {}, DllName: {:p}", dll_name, dll_base);
                    return dll_base;
                }


            }

            current = *(current as *const *const u8);

        }


        // let peb = read_gs_qword(0x60) as *const u8;
        // if peb.is_null() {
        //     return null_mut();
        // }

        // let ldr = *(peb.add(0x18) as *const *const u8);
        // if ldr.is_null() {
        //     return null_mut();
        // }

        // let list_head = ldr.add(0x20);
        // let mut current = *(list_head as *const *const u8);

        // while !current.is_null() && current != list_head {
        //     // InMemoryOrderLinks is 0x10 bytes into LDR_DATA_TABLE_ENTRY.
        //     let entry = current.sub(0x10);

        //     let dll_name_len = *(entry.add(0x58) as *const u16) as usize / 2;
        //     let base_dll_name = *(entry.add(0x60) as *const *const u16);

        //     if !base_dll_name.is_null() && dll_name_len != 0 {
        //         let dll_name_slice = std::slice::from_raw_parts(base_dll_name, dll_name_len);
        //         let dll_name_str = String::from_utf16_lossy(dll_name_slice);

        //         if dll_name_str.eq_ignore_ascii_case(module) {
        //             return *(entry.add(0x30) as *const *mut c_void);
        //         }
        //     }

        //     current = *(current as *const *const u8);
        // }
    }

    null_mut()
}

fn main() {
    let h_kernel32 = get_module_handle("kernel32.dll");

    if h_kernel32.is_null() {
        println!("Failed to get module handle for kernel32.dll");
        return;
    }
}