use std::iter::once;
use windows::{
    Win32::{
        Foundation::{GENERIC_ALL, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE},
    },
    core::PCWSTR,
};

fn main() {
    let filepath: Vec<u16> = "C:\\Temp\\test.txt".encode_utf16().chain(once(0)).collect();

    // let hfile = INVALID_HANDLE_VALUE;

    let hfile: HANDLE = unsafe {
        CreateFileW(
            PCWSTR::from_raw(filepath.as_ptr()),
            GENERIC_ALL.0,
            FILE_SHARE_MODE(0),
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .unwrap()
    };

    if hfile == INVALID_HANDLE_VALUE {
        eprintln!("Failed to create file");
    } else {
        println!("File created successfully");
    }
}
