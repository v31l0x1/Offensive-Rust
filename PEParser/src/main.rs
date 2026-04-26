use windows::Win32::{Foundation::HANDLE, System::{Diagnostics::Debug::WriteProcessMemory, Memory::{self, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx}, Threading::{CreateRemoteThread, GetCurrentProcess, INFINITE, LPTHREAD_START_ROUTINE, WaitForSingleObject}}};
use std::{env, fs::File, io::Read, os::raw::c_void};

fn find_export_directory_info(buffer: &[u8], pointer_to_raw_data: u32, virtual_address_offset: u32) -> u32 {
    println!("\n         [-] [0x{:08X}] [ exportFlags ] : 0x{:08X}", pointer_to_raw_data, u32::from_le_bytes([
        buffer[pointer_to_raw_data as usize],
        buffer[(pointer_to_raw_data + 1) as usize],
        buffer[(pointer_to_raw_data + 2) as usize],
        buffer[(pointer_to_raw_data + 3) as usize],
    ]));

    let time_data_stamp_offset: u32 = pointer_to_raw_data + 4;
    println!(
        "         [-] [0x{:08X}] [ Time/DateStamp ] : 0x{:08X}",
        time_data_stamp_offset,
        u32::from_le_bytes([
            buffer[time_data_stamp_offset as usize],
            buffer[(time_data_stamp_offset + 1) as usize],
            buffer[(time_data_stamp_offset + 2) as usize],
            buffer[(time_data_stamp_offset + 3) as usize],
        ])
    );

    let major_version_offset: u32 = time_data_stamp_offset + 4;
    println!(
        "         [-] [0x{:08X}] [ majorVersion ] : 0x{:04X}",
        major_version_offset,
        u16::from_le_bytes([
            buffer[major_version_offset as usize],
            buffer[(major_version_offset + 1) as usize],
        ])
    );

    let minor_version_offset: u32 = major_version_offset + 2;
    println!(
        "         [-] [0x{:08X}] [ minorVersion ] : 0x{:04X}",
        minor_version_offset,
        u16::from_le_bytes([
            buffer[minor_version_offset as usize],
            buffer[(minor_version_offset + 1) as usize],
        ])
    );

    let name_rva_offset: u32 = minor_version_offset + 2;
    println!(
        "         [-] [0x{:08X}] [ nameRVA ] : 0x{:08X}",
        name_rva_offset,
        u32::from_le_bytes([
            buffer[name_rva_offset as usize],
            buffer[(name_rva_offset + 1) as usize],
            buffer[(name_rva_offset + 2) as usize],
            buffer[(name_rva_offset + 3) as usize],
        ])
    );

    let ordinal_base_offset: u32 = name_rva_offset + 4;
    println!(
        "         [-] [0x{:08X}] [ ordinalBase ] : 0x{:08X}",
        ordinal_base_offset,
        u32::from_le_bytes([
            buffer[ordinal_base_offset as usize],
            buffer[(ordinal_base_offset + 1) as usize],
            buffer[(ordinal_base_offset + 2) as usize],
            buffer[(ordinal_base_offset + 3) as usize],
        ])
    );

    let address_table_entries_offset: u32 = ordinal_base_offset + 4;
    println!(
        "         [-] [0x{:08X}] [ addressTableEntries ] : 0x{:08X} (count of functions in Export Address Table)",
        address_table_entries_offset,
        u32::from_le_bytes([
            buffer[address_table_entries_offset as usize],
            buffer[(address_table_entries_offset + 1) as usize],
            buffer[(address_table_entries_offset + 2) as usize],
            buffer[(address_table_entries_offset + 3) as usize],
        ])
    );

    let number_of_name_pointers_offset: u32 = address_table_entries_offset + 4;
    println!(
        "         [-] [0x{:08X}] [ numberOfNamePointers ] : 0x{:08X} (count of entries in the name pointer table/ordinal table)",
        number_of_name_pointers_offset,
        u32::from_le_bytes([
            buffer[number_of_name_pointers_offset as usize],
            buffer[(number_of_name_pointers_offset + 1) as usize],
            buffer[(number_of_name_pointers_offset + 2) as usize],
            buffer[(number_of_name_pointers_offset + 3) as usize],
        ])
    );

    let export_address_table_rva_offset: u32 = number_of_name_pointers_offset + 4;
    println!(
        "         [-] [0x{:08X}] [ exportAddressTableRVA ] : 0x{:08X} (RVA of Export Address Table)",
        export_address_table_rva_offset,
        u32::from_le_bytes([
            buffer[export_address_table_rva_offset as usize],
            buffer[(export_address_table_rva_offset + 1) as usize],
            buffer[(export_address_table_rva_offset + 2) as usize],
            buffer[(export_address_table_rva_offset + 3) as usize],
        ])
    );

    let name_pointer_table_rva_offset: u32 = export_address_table_rva_offset + 4;
    println!(
        "         [-] [0x{:08X}] [ namePointerRVA ] : 0x{:08X} (RVA of Export Name Pointer Table)",
        name_pointer_table_rva_offset,
        u32::from_le_bytes([
            buffer[name_pointer_table_rva_offset as usize],
            buffer[(name_pointer_table_rva_offset + 1) as usize],
            buffer[(name_pointer_table_rva_offset + 2) as usize],
            buffer[(name_pointer_table_rva_offset + 3) as usize],
        ])
    );

    let ordinal_table_rva_offset: u32 = name_pointer_table_rva_offset + 4;
    println!(
        "         [-] [0x{:08X}] [ ordinalTableRVA ] : 0x{:08X} (RVA of Export Ordinal Table)",
        ordinal_table_rva_offset,
        u32::from_le_bytes([
            buffer[ordinal_table_rva_offset as usize],
            buffer[(ordinal_table_rva_offset + 1) as usize],
            buffer[(ordinal_table_rva_offset + 2) as usize],
            buffer[(ordinal_table_rva_offset + 3) as usize],
        ])
    );

    let export_name_pointer_rva = u32::from_le_bytes([
        buffer[name_pointer_table_rva_offset as usize],
        buffer[(name_pointer_table_rva_offset + 1) as usize],
        buffer[(name_pointer_table_rva_offset + 2) as usize],
        buffer[(name_pointer_table_rva_offset + 3) as usize],
    ]);

    let edata_virtual_address = u32::from_le_bytes([
        buffer[virtual_address_offset as usize],
        buffer[(virtual_address_offset + 1) as usize],
        buffer[(virtual_address_offset + 2) as usize],
        buffer[(virtual_address_offset + 3) as usize],
    ]);

    let export_name_pointer_file_offset = ( export_name_pointer_rva - edata_virtual_address ) + pointer_to_raw_data;
    println!(
        "         [-] [0x{:08X}] [ exportNamePointerRVA ] : 0x{:08X}",
        export_name_pointer_file_offset,
        u32::from_le_bytes([
            buffer[export_name_pointer_file_offset as usize],
            buffer[(export_name_pointer_file_offset + 1) as usize],
            buffer[(export_name_pointer_file_offset + 2) as usize],
            buffer[(export_name_pointer_file_offset + 3) as usize],
        ])
    );

    let symbol_name_rva = u32::from_le_bytes([
        buffer[export_name_pointer_file_offset as usize],
        buffer[(export_name_pointer_file_offset + 1) as usize],
        buffer[(export_name_pointer_file_offset + 2) as usize],
        buffer[(export_name_pointer_file_offset + 3) as usize],
    ]);

    let symbol_file_offset = ( symbol_name_rva - edata_virtual_address ) + pointer_to_raw_data;
    let mut symbol_name: [u8; 256] = [0; 256];
    for i in 0..256 {
        if buffer[(symbol_file_offset + i) as usize] == 0 {
            break;
        }
        symbol_name[i as usize] = buffer[(symbol_file_offset + i) as usize];
    }
    println!("         [-] [0x{:08X}] [ symbolName ] : 0x{:08X} -> {}",
        symbol_file_offset,
        symbol_name_rva,
        String::from_utf8_lossy(&symbol_name)
    );
    let export_address_table_rva = u32::from_le_bytes([
        buffer[export_address_table_rva_offset as usize],
        buffer[(export_address_table_rva_offset + 1) as usize],
        buffer[(export_address_table_rva_offset + 2) as usize],
        buffer[(export_address_table_rva_offset + 3) as usize],
    ]);
    let symbol_rva_offset = ( export_address_table_rva - edata_virtual_address ) + pointer_to_raw_data;
    let symbol_rva = u32::from_le_bytes([
        buffer[symbol_rva_offset as usize],
        buffer[(symbol_rva_offset + 1) as usize],
        buffer[(symbol_rva_offset + 2) as usize],
        buffer[(symbol_rva_offset + 3) as usize],
    ]);
    
    symbol_rva

}

fn find_section_headers(buffer: &[u8], first_section_header_offset: u32, no_of_sections: u16) {
    println!(
        "\n [Section headers start at: 0x{:04X?}]",
        first_section_header_offset
    );

    let mut next_section_header_offset: u32 = first_section_header_offset;
    for i in 0..no_of_sections {
        let header_name: [u8; 8] = [
            buffer[next_section_header_offset as usize],
            buffer[(next_section_header_offset + 1) as usize],
            buffer[(next_section_header_offset + 2) as usize],
            buffer[(next_section_header_offset + 3) as usize],
            buffer[(next_section_header_offset + 4) as usize],
            buffer[(next_section_header_offset + 5) as usize],
            buffer[(next_section_header_offset + 6) as usize],
            buffer[(next_section_header_offset + 7) as usize],
        ];
        println!("\n [+] [ Section Header {} ] ", i);
        println!(
            "     [+] [ 0x{:08X} ] [ Name ] : {}",
            next_section_header_offset,
            String::from_utf8_lossy(&header_name)
        );

        let virtual_size_offset: u32 = next_section_header_offset + 8;
        println!(
            "     [+] [ 0x{:08X} ] [ virtualSize ] : 0x{:08X}",
            virtual_size_offset,
            u32::from_le_bytes([
                buffer[virtual_size_offset as usize],
                buffer[(virtual_size_offset + 1) as usize],
                buffer[(virtual_size_offset + 2) as usize],
                buffer[(virtual_size_offset + 3) as usize],
            ])
        );

        let virtual_address_offset: u32 = virtual_size_offset + 4;
        println!(
            "     [+] [ 0x{:08X} ] [ virtualAddress ] : 0x{:08X}",
            virtual_address_offset,
            u32::from_le_bytes([
                buffer[virtual_address_offset as usize],
                buffer[(virtual_address_offset + 1) as usize],
                buffer[(virtual_address_offset + 2) as usize],
                buffer[(virtual_address_offset + 3) as usize],
            ])
        );

        let size_of_raw_data_offset: u32 = virtual_address_offset + 4;
        println!(
            "     [+] [ 0x{:08X} ] [ sizeOfRawData ] : 0x{:08X}",
            size_of_raw_data_offset,
            u32::from_le_bytes([
                buffer[size_of_raw_data_offset as usize],
                buffer[(size_of_raw_data_offset + 1) as usize],
                buffer[(size_of_raw_data_offset + 2) as usize],
                buffer[(size_of_raw_data_offset + 3) as usize],
            ])
        );

        let pointer_to_raw_data_offset: u32 = size_of_raw_data_offset + 4;
        println!(
            "     [+] [ 0x{:08X} ] [ pointerToRawData ] : 0x{:08X}",
            pointer_to_raw_data_offset,
            u32::from_le_bytes([
                buffer[pointer_to_raw_data_offset as usize],
                buffer[(pointer_to_raw_data_offset + 1) as usize],
                buffer[(pointer_to_raw_data_offset + 2) as usize],
                buffer[(pointer_to_raw_data_offset + 3) as usize],
            ])
        );

        let pointer_to_reloacations_offset: u32 = pointer_to_raw_data_offset + 4;
        println!(
            "     [+] [ 0x{:08X} ] [ pointerToRelocations ] : 0x{:08X}",
            pointer_to_reloacations_offset,
            u32::from_le_bytes([
                buffer[pointer_to_reloacations_offset as usize],
                buffer[(pointer_to_reloacations_offset + 1) as usize],
                buffer[(pointer_to_reloacations_offset + 2) as usize],
                buffer[(pointer_to_reloacations_offset + 3) as usize],
            ])
        );

        let pointer_to_linenumbers_offset: u32 = pointer_to_reloacations_offset + 4;
        println!(
            "     [+] [ 0x{:08X} ] [ pointerToLineNumbers ] : 0x{:08X}",
            pointer_to_linenumbers_offset,
            u32::from_le_bytes([
                buffer[pointer_to_linenumbers_offset as usize],
                buffer[(pointer_to_linenumbers_offset + 1) as usize],
                buffer[(pointer_to_linenumbers_offset + 2) as usize],
                buffer[(pointer_to_linenumbers_offset + 3) as usize],
            ])
        );

        let number_of_relocations_offset: u32 = pointer_to_linenumbers_offset + 4;
        println!(
            "     [+] [ 0x{:08X} ] [ number of Relocations ] : 0x{:04X}",
            number_of_relocations_offset,
            u16::from_le_bytes([
                buffer[number_of_relocations_offset as usize],
                buffer[(number_of_relocations_offset + 1) as usize],
            ])
        );

        let number_of_linenumbers_offset: u32 = number_of_relocations_offset + 2;
        println!(
            "     [+] [ 0x{:08X} ] [ numberOfLineNumbers ] : 0x{:04X}",
            number_of_linenumbers_offset,
            u16::from_le_bytes([
                buffer[number_of_linenumbers_offset as usize],
                buffer[(number_of_linenumbers_offset + 1) as usize],
            ])
        );

        let characteristics_offset: u32 = number_of_linenumbers_offset + 2;
        println!(
            "     [+] [ 0x{:08X} ] [ characteristics ] : 0x{:08X}",
            characteristics_offset,
            u32::from_le_bytes([
                buffer[characteristics_offset as usize],
                buffer[(characteristics_offset + 1) as usize],
                buffer[(characteristics_offset + 2) as usize],
                buffer[(characteristics_offset + 3) as usize],
            ])
        );

        if header_name.starts_with(b".edata") {
            let pointer_to_raw_data = u32::from_le_bytes([
                buffer[pointer_to_raw_data_offset as usize],
                buffer[(pointer_to_raw_data_offset + 1) as usize],
                buffer[(pointer_to_raw_data_offset + 2) as usize],
                buffer[(pointer_to_raw_data_offset + 3) as usize],
            ]);
            let symbol_rva = find_export_directory_info(&buffer, pointer_to_raw_data, virtual_address_offset);
            println!("         [-] [0x{:08X}] [ symbolRVA ] : 0x{:08X}", pointer_to_raw_data, symbol_rva);


            let temp_section_header_offset = first_section_header_offset;
            for i in 0..no_of_sections {
                let section_virtual_address_offset: u32 = first_section_header_offset + 12; // virtualAddress is at offset 12 in section header
                let section_virtual_address = u32::from_le_bytes([
                    buffer[section_virtual_address_offset as usize],
                    buffer[(section_virtual_address_offset + 1) as usize],
                    buffer[(section_virtual_address_offset + 2) as usize],
                    buffer[(section_virtual_address_offset + 3) as usize],
                ]);
                // SizeofRawData offset is 4 bytes from VirtualAddress (VirtualAddres == 4)
                let section_size_of_raw_data_offset: u32 = section_virtual_address_offset + 4;
                let section_of_raw_data = u32::from_le_bytes([
                    buffer[section_size_of_raw_data_offset as usize],
                    buffer[(section_size_of_raw_data_offset + 1) as usize],
                    buffer[(section_size_of_raw_data_offset + 2) as usize],
                    buffer[(section_size_of_raw_data_offset + 3) as usize],
                ]);
                let section_pointer_to_raw_data_offset: u32 = section_size_of_raw_data_offset + 4;
                let section_pointer_to_raw_data = u32::from_le_bytes([
                    buffer[section_pointer_to_raw_data_offset as usize],
                    buffer[(section_pointer_to_raw_data_offset + 1) as usize],
                    buffer[(section_pointer_to_raw_data_offset + 2) as usize],
                    buffer[(section_pointer_to_raw_data_offset + 3) as usize],
                ]);

                if (( symbol_rva > section_virtual_address) && (symbol_rva < (section_virtual_address + section_of_raw_data))) {
                    let symbol_file_offset = ( symbol_rva - section_virtual_address ) + section_pointer_to_raw_data;
                    println!("\n\t         [*] [0x{:08X}] [ symbolFileOffset ] : 0x{:08X}", symbol_rva, symbol_file_offset);
                    
                    unsafe {
                        let exec_buffer = VirtualAllocEx(GetCurrentProcess(), Some(std::ptr::null()), buffer.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        WriteProcessMemory(GetCurrentProcess(), exec_buffer, buffer.as_ptr() as *const c_void, buffer.len(), None);
                        let symbol_executable_address = exec_buffer.add(symbol_file_offset as usize);
                        let h_thread = CreateRemoteThread(GetCurrentProcess(), Some(std::ptr::null_mut()), 1024*1024, Some(std::mem::transmute(symbol_executable_address)), Some(std::ptr::null_mut()), 0, Some(std::ptr::null_mut())).unwrap();
                        WaitForSingleObject(h_thread, INFINITE);
                    }

                    break;
                }
            }
        }

        next_section_header_offset += 40; // Size of a section header
    }
}

fn main() {
    let pe_path: Vec<String> = env::args().collect();
    if pe_path.len() != 2 {
        println!("Usage: pe_parser <path_to_pe_file>");
        return;
    }

    println!("[+] Parsing : {} ", pe_path.get(1).unwrap());

    let mut fd = match File::open(pe_path.get(1).unwrap()) {
        Ok(fd) => fd,
        Err(err) => {
            println!("[-] Failed to open file: {}", err);
            return;
        }
    };

    let mut buffer = Vec::new();

    fd.read_to_end(&mut buffer);

    println!("[+] File size: {} bytes", buffer.len());

    println!(
        "[ 0x00000000 ] [ DOS Header ] : {}",
        String::from_utf8_lossy(&buffer[0..2])
    );

    let initial_offset: u32 = 0x3C;
    // Read the PE header offset from the DOS header at offset 0x3C
    // Reconstruct the 32-bit little-endian integer from 4 bytes
    let pe_header_offset: u32 = buffer[initial_offset as usize] as u32;
    // println!("[+] PE header offset: 0x{:X}", pe_header_offset);
    println!(
        "[ 0x{:08X?} ] [ peHeader offset ] : 0x{:2X?}",
        initial_offset, pe_header_offset
    );
    println!(
        "[ 0x{:08X?} ] [ peHeader ] : {}",
        pe_header_offset,
        String::from_utf8_lossy(
            &buffer[pe_header_offset as usize..(pe_header_offset + 2) as usize]
        )
    );

    let machine_type_offset = pe_header_offset + 4;
    println!(
        "[ 0x{:08X?} ] [ machineType ] : 0x{:04X?}",
        machine_type_offset,
        u16::from_le_bytes([
            buffer[machine_type_offset as usize],
            buffer[(machine_type_offset + 1) as usize]
        ])
    );

    let no_of_sections_offset: u32 = machine_type_offset + 2;
    let no_of_sections = u16::from_le_bytes([
        buffer[no_of_sections_offset as usize],
        buffer[(no_of_sections_offset + 1) as usize],
    ]);
    println!(
        "[ 0x{:08X?} ] [ noOfSections ] : {}",
        no_of_sections_offset, no_of_sections
    );

    let time_date_stamp_offset: u32 = no_of_sections_offset + 2;
    let time_date_stamp = u32::from_le_bytes([
        buffer[time_date_stamp_offset as usize],
        buffer[(time_date_stamp_offset + 1) as usize],
        buffer[(time_date_stamp_offset + 2) as usize],
        buffer[(time_date_stamp_offset + 3) as usize],
    ]);
    println!(
        "[ 0x{:08X?} ] [ timeDateStamp ] : 0x{:08X?}",
        time_date_stamp_offset, time_date_stamp
    );

    let pointer_to_symbol_table_offset: u32 = time_date_stamp_offset + 4;
    let pointer_to_symbol_table = u32::from_le_bytes([
        buffer[pointer_to_symbol_table_offset as usize],
        buffer[(pointer_to_symbol_table_offset + 1) as usize],
        buffer[(pointer_to_symbol_table_offset + 2) as usize],
        buffer[(pointer_to_symbol_table_offset + 3) as usize],
    ]);
    println!(
        "[ 0x{:08X?} ] [ pointerToSymbolTable ] : 0x{:08X?}",
        pointer_to_symbol_table_offset, pointer_to_symbol_table
    );

    let number_of_symbols_offset: u32 = pointer_to_symbol_table_offset + 4;
    let number_of_symbols = u32::from_le_bytes([
        buffer[number_of_symbols_offset as usize],
        buffer[(number_of_symbols_offset + 1) as usize],
        buffer[(number_of_symbols_offset + 2) as usize],
        buffer[(number_of_symbols_offset + 3) as usize],
    ]);
    println!(
        "[ 0x{:08X?} ] [ numberOfSymbols ] : 0x{:08X?}",
        number_of_symbols_offset, number_of_symbols
    );

    let size_of_optional_header_offset: u32 = number_of_symbols_offset + 4;
    let size_of_optional_header = u16::from_le_bytes([
        buffer[size_of_optional_header_offset as usize],
        buffer[(size_of_optional_header_offset + 1) as usize],
    ]);
    println!(
        "[ 0x{:08X?} ] [ sizeOfOptionalHeader ] : 0x{:04X?}",
        size_of_optional_header_offset, size_of_optional_header
    );

    let characteristics_offset: u32 = size_of_optional_header_offset + 2;
    let characteristics = u16::from_le_bytes([
        buffer[characteristics_offset as usize],
        buffer[(characteristics_offset + 1) as usize],
    ]);
    println!(
        "[ 0x{:08X?} ] [ characteristics ] : 0x{:04X?}",
        characteristics_offset, characteristics
    );

    let first_section_header_offset: u32 =
        characteristics_offset + 2 + size_of_optional_header as u32;

    find_section_headers(&buffer, first_section_header_offset, no_of_sections);
}
