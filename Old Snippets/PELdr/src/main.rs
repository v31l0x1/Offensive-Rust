use std::{fs::File, io::Read, os::raw::c_void, sync::OnceLock};
use windows::Win32::{
    Foundation::{CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GetLastError, HANDLE},
    System::{
        Diagnostics::Debug::{
            CONTEXT_FULL_AMD64, GetThreadContext, IMAGE_DATA_DIRECTORY,
            IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS64,
            IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER,
            SetThreadContext,
        },
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
            PAGE_READWRITE, PAGE_WRITECOPY, VirtualAlloc, VirtualFree, VirtualProtect,
        },
        SystemServices::{
            IMAGE_BASE_RELOCATION, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
            IMAGE_NT_SIGNATURE,
        },
        Threading::{
            CreateThread, GetCurrentProcess, GetCurrentThread, INFINITE, LPTHREAD_START_ROUTINE,
            ResumeThread, SuspendThread, THREAD_CREATION_FLAGS, WaitForSingleObject,
        },
        WindowsProgramming::IMAGE_THUNK_DATA64,
    },
};
use windows::core::PCSTR;

macro_rules! IMAGE_FIRST_SECTION {
    ($ntheader:expr) => {{
        let nt_hdr = $ntheader as *const IMAGE_NT_HEADERS64;
        let optional_header_ptr = std::ptr::addr_of!((*nt_hdr).OptionalHeader) as usize;
        let offset = (*nt_hdr).FileHeader.SizeOfOptionalHeader as usize;
        (optional_header_ptr + offset) as *const IMAGE_SECTION_HEADER
    }};
}

static BUFFER: OnceLock<Vec<u8>> = OnceLock::new();

#[allow(non_snake_case)]
fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() < 2 {
        println!("Usage: {} <input_file>", args[0]);
        return;
    }

    let mut fd = match File::open(args.get(1).unwrap()) {
        Ok(fd) => fd,
        Err(err) => {
            println!("Error opening file: {}", err);
            return;
        }
    };

    let mut buffer = Vec::new();

    fd.read_to_end(&mut buffer).expect("Error reading file");

    println!("[+] File size: {} bytes", buffer.len());

    let _ = BUFFER.set(buffer);

    unsafe {
        let hCurrent = GetCurrentThread();

        let mut hDup = HANDLE::default();

        match DuplicateHandle(
            GetCurrentProcess(),
            hCurrent,
            GetCurrentProcess(),
            &mut hDup,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        ) {
            Ok(_) => {}
            Err(err) => {
                println!("Error duplicating handle: {}", err);
                return;
            }
        };

        let thread_start: LPTHREAD_START_ROUTINE = Some(RunMe);

        let hWorker = match CreateThread(
            None,
            0,
            thread_start,
            Some(&mut hDup as *mut HANDLE as *mut c_void),
            THREAD_CREATION_FLAGS(0),
            None,
        ) {
            Ok(hWorker) => hWorker,
            Err(err) => {
                println!("Error creating thread: {}", err);
                return;
            }
        };

        WaitForSingleObject(hWorker, INFINITE);

        let _ = CloseHandle(hWorker);
        let _ = CloseHandle(hDup);
    }
}


#[allow(non_snake_case, unused_variables, unused_assignments)]
unsafe extern "system" fn RunMe(parameter: *mut c_void) -> u32 {
    unsafe {
        let hThread = *(parameter as *mut HANDLE);

        SuspendThread(hThread);

        let _buffer_len = BUFFER.get().map(|b| b.len()).unwrap_or(0);

        let dosHeader = BUFFER.get().unwrap().as_ptr()
            as *const windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;

        let ntHeaders = (BUFFER.get().unwrap().as_ptr() as usize + (*dosHeader).e_lfanew as usize)
            as *const windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;

        if (*ntHeaders).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid PE format");
            ResumeThread(hThread);
            return 0;
        }

        let imgSize = (*ntHeaders).OptionalHeader.SizeOfImage;
        let hdrSize = (*ntHeaders).OptionalHeader.SizeOfHeaders;

        let imageBase = VirtualAlloc(
            None,
            imgSize as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if imageBase.is_null() {
            println!("[-] VirtualAlloc failed: {}", GetLastError().0);
            ResumeThread(hThread);
            return 0;
        }

        std::ptr::copy_nonoverlapping(
            BUFFER.get().unwrap().as_ptr(),
            imageBase as *mut u8,
            hdrSize as usize,
        );

        let ntHeaders =
            (imageBase as usize + (*dosHeader).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

        let secHdr = IMAGE_FIRST_SECTION!(ntHeaders);

        for i in 0..(*ntHeaders).FileHeader.NumberOfSections {
            let sec = &*secHdr.add(i as usize);

            std::ptr::copy_nonoverlapping(
                BUFFER
                    .get()
                    .unwrap()
                    .as_ptr()
                    .add(sec.PointerToRawData as usize),
                (imageBase as usize + sec.VirtualAddress as usize) as *mut u8,
                sec.SizeOfRawData as usize,
            );
        }

        let dataDir =
            (*ntHeaders).OptionalHeader.DataDirectory.as_ptr() as *const IMAGE_DATA_DIRECTORY;

        let relocDirEntry = *dataDir.add(IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize);

        if relocDirEntry.VirtualAddress == 0 {
            println!("[-] No relocation directory found");
            VirtualFree(imageBase, 0, MEM_RELEASE).expect("Failed to free virtual memory");
            ResumeThread(hThread);
            return 0;
        }

        let mut relBlock = (imageBase as usize + relocDirEntry.VirtualAddress as usize)
            as *mut IMAGE_BASE_RELOCATION;
        let delta = imageBase as isize - (*ntHeaders).OptionalHeader.ImageBase as isize;

        while (*relBlock).VirtualAddress != 0 {
            if (*relBlock).SizeOfBlock >= size_of::<IMAGE_BASE_RELOCATION>() as u32 {
                let entries =
                    ((*relBlock).SizeOfBlock - size_of::<IMAGE_BASE_RELOCATION>() as u32) / 2;
                let relEntry = relBlock.add(1) as *const u16;

                for i in 0..entries {
                    if relEntry.add(i as usize).read() != 0 {
                        let offset = relEntry.add(i as usize).read() & 0xFFF;
                        let rtype = relEntry.add(i as usize).read() >> 12;

                        if rtype == 0xA {
                            let patchAddr = (imageBase as usize
                                + (*relBlock).VirtualAddress as usize
                                + offset as usize)
                                as *mut usize;
                            patchAddr.write(patchAddr.read().wrapping_add(delta as usize));
                        }
                    }
                }
            }
            relBlock = (relBlock as usize + (*relBlock).SizeOfBlock as usize)
                as *mut IMAGE_BASE_RELOCATION;
        }

        let importDir = (*ntHeaders)
            .OptionalHeader
            .DataDirectory
            .as_ptr()
            .add(IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize)
            as *const IMAGE_DATA_DIRECTORY;

        if (*importDir).VirtualAddress == 0 {
            println!("[-] No import directory found");
            VirtualFree(imageBase, 0, MEM_RELEASE).expect("Failed to free virtual memory");
            ResumeThread(hThread);
            return 0;
        }

        let mut impDesc = (imageBase as usize + (*importDir).VirtualAddress as usize)
            as *const IMAGE_IMPORT_DESCRIPTOR;

        while (*impDesc).Name != 0 {
            let dllName = (imageBase as usize + (*impDesc).Name as usize) as *const i8;

            println!(
                "[+] Loading DLL: {}",
                std::ffi::CStr::from_ptr(dllName)
                    .to_str()
                    .unwrap_or("Invalid UTF-8")
            );
            let hMod = LoadLibraryA(PCSTR::from_raw(dllName as *const u8)).unwrap();

            if hMod.is_invalid() {
                println!(
                    "[-] Failed to load DLL: {}",
                    std::ffi::CStr::from_ptr(dllName)
                        .to_str()
                        .unwrap_or("Invalid UTF-8")
                );
                VirtualFree(imageBase, 0, MEM_RELEASE).expect("Failed to free virtual memory");
                ResumeThread(hThread);
                return 0;
            } else {
                let pNames = match (*impDesc).Anonymous.OriginalFirstThunk {
                    0 => imageBase as usize + (*impDesc).FirstThunk as usize,
                    _ => imageBase as usize + (*impDesc).Anonymous.OriginalFirstThunk as usize,
                };

                let mut pAddr = (imageBase as usize + (*impDesc).FirstThunk as usize)
                    as *mut IMAGE_THUNK_DATA64;

                while (*pAddr).u1.AddressOfData != 0 {
                    let mut pFunc = 0 as u64;

                    if (*pAddr).u1.Ordinal & 0x8000000000000000 != 0 {
                        let ordinal = (*pAddr).u1.Ordinal & 0xFFFF;
                        if let Some(func) = GetProcAddress(hMod, PCSTR(ordinal as *const u8)) {
                            pFunc = func as u64;
                        }
                    } else {
                        let impByName = (imageBase as usize + (*pAddr).u1.AddressOfData as usize)
                            as *const IMAGE_IMPORT_BY_NAME;
                        let funcName =
                            std::ffi::CStr::from_ptr((*impByName).Name.as_ptr() as *const i8)
                                .to_str()
                                .unwrap_or("Invalid UTF-8");
                        if let Some(func) =
                            GetProcAddress(hMod, PCSTR(funcName.as_ptr() as *const u8))
                        {
                            pFunc = func as u64;
                        }
                    }

                    (*pAddr).u1.Function = pFunc;
                    pAddr = pAddr.add(1);
                }
            }

            impDesc = impDesc.add(1);
        }

        let numSections = (*ntHeaders).FileHeader.NumberOfSections;

        for i in 0..numSections {
            let sec = secHdr.add(i as usize);
            let secVA = imageBase as usize + (*sec).VirtualAddress as usize;
            let secSize = if (*sec).Misc.VirtualSize != 0 {
                (*sec).Misc.VirtualSize as usize
            } else {
                (*sec).SizeOfRawData as usize
            };
            let mut protect = PAGE_READONLY;
            let mut oldProtect = PAGE_PROTECTION_FLAGS::default();

            let chars = (*sec).Characteristics;
            let has_read = (chars & IMAGE_SCN_MEM_READ).0 != 0;
            let has_write = (chars & IMAGE_SCN_MEM_WRITE).0 != 0;
            let has_execute = (chars & IMAGE_SCN_MEM_EXECUTE).0 != 0;

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

            if secSize > 0 {
                let _ = VirtualProtect(secVA as *const c_void, secSize, protect, &mut oldProtect);
            }
        }

        let mut ctx = windows::Win32::System::Diagnostics::Debug::CONTEXT::default();
        ctx.ContextFlags = CONTEXT_FULL_AMD64;

        match GetThreadContext(hThread, &mut ctx) {
            Ok(_) => {}
            Err(err) => {
                println!("[-] GetThreadContext failed: {}", err);
                VirtualFree(imageBase, 0, MEM_RELEASE).expect("Failed to free virtual memory");
                ResumeThread(hThread);
                return 0;
            }
        };

        ctx.Rip = imageBase as u64 + (*ntHeaders).OptionalHeader.AddressOfEntryPoint as u64;

        match SetThreadContext(hThread, &ctx) {
            Ok(_) => {}
            Err(err) => {
                println!("[-] SetThreadContext failed: {}", err);
                VirtualFree(imageBase, 0, MEM_RELEASE).expect("Failed to free virtual memory");
                ResumeThread(hThread);
                return 0;
            }
        };

        WaitForSingleObject(hThread, 1000);
        ResumeThread(hThread);
    }

    return 0;
}
