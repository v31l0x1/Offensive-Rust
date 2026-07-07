use windows::Win32::Foundation::HWND;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::core::s;


// type HelloWorldFn = unsafe extern "C" fn() -> ();

// #[allow(non_snake_case)]
// fn main() {
//     unsafe {

//         let hModule = match GetModuleHandleA(s!("Hello_DLL.dll")) {
//             Ok(hModule) => hModule,
//             Err(_) => LoadLibraryA(s!("Hello_DLL.dll")).unwrap(),
//         };

//         println!("Loaded Hello_DLL.dll: {:?}", hModule);

//         let p_hello_world = GetProcAddress(hModule, s!("hello_world")).unwrap();
//         let hello_world: HelloWorldFn = std::mem::transmute(p_hello_world);
//         hello_world();
//     }
// }


type fnMessageBoxA = unsafe extern "C" fn(
    hwnd: HWND,
    lptext: *const u8,
    lpcaption: *const u8,
    utype: u32,
) -> i32;


#[allow(non_snake_case)]
fn main() {
    unsafe {
        let hModule = match GetModuleHandleA(s!("user32.dll")) {
            Ok(hModule) => hModule,
            Err(_) => LoadLibraryA(s!("user32.dll")).unwrap(),
        };

        let pMessageBoxA = GetProcAddress(hModule, s!("MessageBoxA")).unwrap();
        let message_box_a: fnMessageBoxA = std::mem::transmute(pMessageBoxA);
        let text = b"Hello from Rust!\0";
        let caption = b"Message Box\0";
        message_box_a(
            HWND::default(),
            text.as_ptr(),
            caption.as_ptr(),
            0,
        );
    }
}