use std::{
    char,
    ffi::CStr,
    fs::{self, File},
    io::Read,
    ops::Add,
    str::from_utf8,
    thread::current,
};

use std::process::exit;

use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_HEADER,
    IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER, IMAGE_THUNK_DATA,
    PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS,
};

fn hex_dump(bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        print!("{:08X}: ", i * 16);
        for byte in chunk {
            print!("{:02X} ", byte);
        }
        for _ in 0..(16 - chunk.len()) {
            print!("   ");
        }
        print!("|");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <path_to_pe_file> --hex", args[0]);
        std::process::exit(1);
    }

    println!("[+] Reading PE file: {}", args.get(1).unwrap());

    let mut fd = match File::open(args.get(1).unwrap()) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Error opening file: {}", e);
            std::process::exit(1);
        }
    };

    let mut buffer: Vec<u8> = Vec::new();

    fd.read_to_end(&mut buffer).unwrap();

    println!("[+] File size: {} bytes\n", buffer.len());

    if buffer.len() < 64 {
        eprintln!("Error: File is too small to be a valid PE file.");
        std::process::exit(1);
    }

    if args.get(2) == Some(&"--hex".to_string()) {
        println!("Hex dump of the file:");
        hex_dump(&buffer);
        return;
    }

    unsafe {
        let dos_header: PIMAGE_DOS_HEADER = buffer.as_ptr() as PIMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS signature: 0x{:X}", (*dos_header).e_magic);
            std::process::exit(1);
        }

        let nt_headers_offset = (*dos_header).e_lfanew as usize;

        let nt_headers = buffer.as_ptr().add(nt_headers_offset) as PIMAGE_NT_HEADERS;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT signature: 0x{:X}", (*nt_headers).Signature);
            exit(1);
        }

        print!("File Header:\n");

        let machine = (*nt_headers).FileHeader.Machine;
        let sections = (*nt_headers).FileHeader.NumberOfSections;
        let time_date_stamp = (*nt_headers).FileHeader.TimeDateStamp;
        let number_of_symbols = (*nt_headers).FileHeader.NumberOfSymbols;
        let size_of_optional_header = (*nt_headers).FileHeader.SizeOfOptionalHeader;
        let characteristics = (*nt_headers).FileHeader.Characteristics;
        println!("  Machine: 0x{:X}", machine);
        println!("  Number of sections: {}", sections);
        println!("  Time/Date Stamp: {:X}", time_date_stamp);
        println!("  Number of symbols: {}", number_of_symbols);
        println!("  Size of optional header: {}", size_of_optional_header);
        // println!("  Characteristics: 0x{:X}", characteristics);
        println!(
            "  Characteristics: {:?}",
            characteristics_labels(characteristics)
        );

        print!("\nSection Headers:\n");

        let first_section = (nt_headers as *const u8).add(size_of::<IMAGE_NT_HEADERS>())
            as *const IMAGE_SECTION_HEADER;

        println!(
            "  {:<10} {:<11} {:<15} {:<10} {:<10} {:<10}",
            "Name", "VirtualSize", "VirtualAddress", "Raw Size", "Raw Address", "Protection"
        );
        println!(
            "  ------------------------------------------------------------------------------"
        );

        for i in 0..(*nt_headers).FileHeader.NumberOfSections {
            let section: *const IMAGE_SECTION_HEADER = first_section.add(i as usize);

            let name = from_utf8(&(*section).Name)
                .unwrap()
                .trim_matches(char::from(0));

            println!(
                "  {:<10} {:<11X} {:<15X} {:<10} {:<10} {:<10}",
                name,
                (*section).Misc.VirtualSize(),
                (*section).VirtualAddress,
                (*section).SizeOfRawData,
                (*section).PointerToRawData,
                get_characteristics(&(*section))
            );
        }

        println!("\nExport Table:\n");

        let export_directory_rva = (*nt_headers).OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress;

        println!(
            "  {:<50} {:<10} {:<10} {:<10}",
            "Function Name", "Ordinal", "RVA", "Address"
        );
        println!(
            "  ------------------------------------------------------------------------------"
        );

        if export_directory_rva as u32 == 0 {
            println!("[-] No export table found.");
        } else {
            let export_directory =
                buffer.as_ptr().add(export_directory_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

            let address_of_functions = buffer
                .as_ptr()
                .add((*export_directory).AddressOfFunctions as usize)
                as *const u32;
            let address_of_names = buffer
                .as_ptr()
                .add((*export_directory).AddressOfNames as usize)
                as *const u32;
            let address_of_name_ordinals = buffer
                .as_ptr()
                .add((*export_directory).AddressOfNameOrdinals as usize)
                as *const u16;

            for i in 0..(*export_directory).NumberOfNames as isize {
                let function_name =
                    buffer.as_ptr().add(*address_of_names.offset(i) as usize) as *const i8;

                let oridinal = *address_of_name_ordinals.offset(i) as usize;

                if oridinal >= (*export_directory).NumberOfFunctions as usize {
                    continue;
                }

                let function_rva = *address_of_functions.add(oridinal) as usize;
                let function_address = buffer.as_ptr().add(function_rva as usize);

                let c_str = CStr::from_ptr(function_name);

                if let Ok(function_str) = c_str.to_str() {
                    println!(
                        "  {:<50} {:<10} 0x{:08X} {:p}",
                        function_str, i, function_rva, function_address
                    );
                }
            }
        }

        println!("\nImport Table:\n");

        let image_directory_rva = (*nt_headers).OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
            .VirtualAddress;

        let mut image_directory =
            buffer.as_ptr().add(image_directory_rva as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

        while (*image_directory).Name != 0 {
            let dll_name_ptr = buffer.as_ptr().add((*image_directory).Name as usize);
            let dll_name = CStr::from_ptr(dll_name_ptr as *const i8);
            // println!("  {}", dll_name.to_str().unwrap_or("Invalid UTF-8"));
            // println!("    Function: ");
            println!("  [{}]", dll_name.to_str().unwrap_or("Invalid UTF-8"));
            // println!("    {:<50}", "Function Names");
            print!("  -----------------------------------------------------\n");

            let original_first_thunk = *(*image_directory).u.OriginalFirstThunk();

            if original_first_thunk != 0 {
                let mut thunk =
                    buffer.as_ptr().add(original_first_thunk as usize) as *const IMAGE_THUNK_DATA;

                while *(*thunk).u1.AddressOfData() != 0 {
                    if *(*thunk).u1.Ordinal() & IMAGE_ORDINAL_FLAG != 0 {
                        let oridinal = *(*thunk).u1.Ordinal() & 0xFFFF;
                        println!("      Ordinal: {}", oridinal);
                    } else {
                        let image_by_name_ptr =
                            buffer.as_ptr().add(*(*thunk).u1.AddressOfData() as usize);
                        let import_by_name = image_by_name_ptr as *const IMAGE_IMPORT_BY_NAME;
                        let func_name =
                            CStr::from_ptr((*import_by_name).Name.as_ptr() as *const i8);
                        println!("    {}", func_name.to_str().unwrap_or("Invalid UTF-8"));
                    }
                    thunk = thunk.add(1);
                }
            }

            image_directory = image_directory.add(1);
        }
    }
}

fn get_characteristics(&section: &IMAGE_SECTION_HEADER) -> &'static str {
    let characteristics = section.Characteristics;
    let read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    let write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    let execute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

    if execute & read & write {
        return "PAGE_EXECUTE_READWRITE";
    } else if execute & read {
        return "PAGE_EXECUTE_READ";
    } else if execute & write {
        return "PAGE_EXECUTE_WRITE";
    } else if read & write {
        return "PAGE_READWRITE";
    } else if execute {
        return "PAGE_EXECUTE";
    } else if read {
        return "PAGE_READ";
    } else if write {
        return "PAGE_WRITE";
    } else {
        return "PAGE_NOACCESS";
    }
}

fn characteristics_labels(c: u16) -> Vec<&'static str> {
    let mut labels = Vec::new();

    if c & 0x0001 != 0 {
        labels.push("RELOCS_STRIPPED");
    }
    if c & 0x0002 != 0 {
        labels.push("EXECUTABLE_IMAGE");
    }
    if c & 0x0004 != 0 {
        labels.push("LINE_NUMS_STRIPPED");
    }
    if c & 0x0008 != 0 {
        labels.push("LOCAL_SYMS_STRIPPED");
    }
    if c & 0x0010 != 0 {
        labels.push("AGGRESSIVE_WS_TRIM");
    }
    if c & 0x0020 != 0 {
        labels.push("LARGE_ADDRESS_AWARE");
    }
    if c & 0x0080 != 0 {
        labels.push("BYTES_REVERSED_LO");
    }
    if c & 0x0100 != 0 {
        labels.push("32BIT_MACHINE");
    }
    if c & 0x0200 != 0 {
        labels.push("DEBUG_STRIPPED");
    }
    if c & 0x0400 != 0 {
        labels.push("REMOVABLE_RUN_FROM_SWAP");
    }
    if c & 0x0800 != 0 {
        labels.push("NET_RUN_FROM_SWAP");
    }
    if c & 0x1000 != 0 {
        labels.push("SYSTEM");
    }
    if c & 0x2000 != 0 {
        labels.push("DLL");
    }
    if c & 0x4000 != 0 {
        labels.push("UP_SYSTEM_ONLY");
    }
    if c & 0x8000 != 0 {
        labels.push("BYTES_REVERSED_HI");
    }

    labels
}
