mod getmod;
mod getprocaddr;

use getmod::get_mod;
use getprocaddr::getprocaddr;

fn main() {
    let mod_addr = get_mod("kernel32.dll");

    println!("Module address: 0x{:016x}", mod_addr as u64);

    let func_addr = getprocaddr(mod_addr, "LoadLibraryA");
    println!("Function address: 0x{:016x}", func_addr as u64);
}
