mod getmod;

use getmod::get_mod;

fn main() {
    let mod_addr = unsafe { get_mod("kernel32.dll") };

    println!("Module address: 0x{:016x}", mod_addr as u64);
}
