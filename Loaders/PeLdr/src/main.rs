use std::{
    fs::File, intrinsics::copy_nonoverlapping, io::Read, os::raw::c_void, process::exit,
    ptr::null_mut, str::from_utf8, sync::OnceLock,
};

use windows_sys::Win32::{
    Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle},
    System::{
        Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER},
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc},
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
        Threading::{
            CreateThread, GetCurrentProcess, GetCurrentThread, ResumeThread, SuspendThread,
            WaitForSingleObject,
        },
    },
};

static BUFFER: OnceLock<Vec<u8>> = OnceLock::new();

macro_rules! IMAGE_FIRST_SECTION {
    ($ntheader:expr) => {{
        let nt_hdr = $ntheader as *const IMAGE_NT_HEADERS64;
        let optional_header_ptr = std::ptr::addr_of!((*nt_hdr).OptionalHeader) as usize;
        let offset = (*nt_hdr).FileHeader.SizeOfOptionalHeader as usize;
        (optional_header_ptr + offset) as *const IMAGE_SECTION_HEADER
    }};
}

unsafe extern "system" fn run_me(param: *mut c_void) -> u32 {
    unsafe {
        let thread_handle = param as *mut c_void;

        SuspendThread(thread_handle);

        let buffer = BUFFER
            .get()
            .map(|b| b.as_ptr() as *const u8)
            .unwrap_or(null_mut());

        let _buf_len = BUFFER.get().map(|b| b.len()).unwrap_or(0);

        let dos_header = BUFFER
            .get()
            .map(|b| b.as_ptr() as *const u8)
            .unwrap_or(null_mut()) as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS signature");
            return 1;
        }

        let nt_header = buffer.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT signature");
            return 1;
        }

        let image_size = (*nt_header).OptionalHeader.SizeOfImage as usize;
        let header_size = (*nt_header).OptionalHeader.SizeOfHeaders as usize;

        let image_base = VirtualAlloc(
            null_mut(),
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if image_base.is_null() {
            println!("[-] Failed to allocate memory for image");
            return 1;
        }

        copy_nonoverlapping(
            BUFFER.get().unwrap().as_ptr(),
            image_base as *mut u8,
            header_size as usize,
        );

        let sec_hdr = IMAGE_FIRST_SECTION!(nt_header);

        for i in 0..(*nt_header).FileHeader.NumberOfSections {
            let section = sec_hdr.add(i as usize);

            let name = from_utf8(&(*section).Name)
                .unwrap()
                .trim_matches(char::from(0));

            println!("[+] Copying section: {} to memory", name);

            copy_nonoverlapping(
                BUFFER
                    .get()
                    .unwrap()
                    .as_ptr()
                    .add((*sec_hdr).PointerToRawData as usize),
                (image_base as usize + (*section).VirtualAddress as usize) as *mut u8,
                (*section).SizeOfRawData as usize,
            );
        }

        ResumeThread(thread_handle);
    }

    0
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("[+] Usage: {} proc.enc <arguments>", args[0]);
        exit(0);
    }

    let mut proc_args: Vec<String> = Vec::new();

    if args.len() > 2 {
        proc_args = args[2..].to_vec();
    }

    let path = args[1].clone();

    println!("[+] Executing: {} with arguments {:?}", path, proc_args);

    let mut file = File::open(path).expect("Failed to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");

    BUFFER.set(buffer).expect("Failed to set buffer");

    unsafe {
        let current_thread = GetCurrentThread();
        let mut dup_handle: *mut c_void = null_mut();

        if DuplicateHandle(
            GetCurrentProcess(),
            current_thread,
            GetCurrentProcess(),
            &mut dup_handle,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        ) == 0
        {
            println!("[-] Failed to duplicate handle");
            return;
        }

        let thread_handle = CreateThread(null_mut(), 0, Some(run_me), null_mut(), 0, null_mut());

        if thread_handle.is_null() {
            println!("[-] Failed to create thread");
            return;
        }

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);

        return;
    }
}
