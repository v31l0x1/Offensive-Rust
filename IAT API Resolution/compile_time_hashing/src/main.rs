pub const fn ror_13_ansi(buf: &[u8]) -> u32 {
    let mut result: u32 = 0;
    let mut i = 0;
    while i < buf.len() {
        let mut char = buf[i];
        if char > b'A' && char < b'Z' {
            char += 0x20;
        }
        result = result.rotate_right(13).wrapping_add(char as u32);
        i += 1;
    }
    result
}

pub const fn ror_13_wide(buf: &[u16]) -> u32 {
    let mut result: u32 = 0;
    let mut i = 0;
    while i < buf.len() {
        let mut char = buf[i];
        if char > b'A' as u16 && char < b'Z' as u16 {
            char += 0x20;
        }
        result = result.rotate_right(13).wrapping_add(char as u32);
        i += 1;
    }
    result
}

fn main() {
    let kernel32_ansi: u32 = ror_13_ansi(b"kernel32.dll");
    let kernel32_wide: u32 = ror_13_wide(
        "kernel32.dll"
            .encode_utf16()
            .collect::<Vec<u16>>()
            .as_slice(),
    );

    println!("KERNEL32_ANSI: {:#X}", kernel32_ansi);

    println!("KERNEL32_WIDE: {:#X}", kernel32_wide);

    let ntdll_ansi = ror_13_ansi(b"ntdll.dll");
    let ntdll_wide = ror_13_wide("ntdll.dll".encode_utf16().collect::<Vec<u16>>().as_slice());

    println!("NTDLL_ANSI: {:#X}", ntdll_ansi);
    println!("NTDLL_WIDE: {:#X}", ntdll_wide);
}
