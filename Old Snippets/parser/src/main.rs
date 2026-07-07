use std::{fs::File, io::Read, mem::size_of, os::raw::c_void};

use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_FILE_DLL, IMAGE_FILE_MACHINE_I386, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS, IMAGE_NT_OPTIONAL_HDR_MAGIC, IMAGE_NT_SIGNATURE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER, IMAGE_SUBSYSTEM_NATIVE, PIMAGE_DOS_HEADER
};

#[allow(unused)]
fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() < 2 {
        println!("Usage: {} <file_path>", args[0]);
        return;
    }

    let mut file_path = &args[1];

    let mut fd = match File::open(file_path) {
        Ok(fd) => fd,
        Err(err) => {
            println!("Error opening file {}: {}", file_path, err);
            return;
        }
    };

    let mut buffer = Vec::new();

    match fd.read_to_end(&mut buffer) {
        Ok(_) => {}
        Err(err) => {
            println!("Error reading file {}: {}", file_path, err);
            return;
        }
    };

    println!("[+] {} is of size : {} bytes", file_path, buffer.len());

    unsafe {
        let dos_header = &*(buffer.as_ptr() as PIMAGE_DOS_HEADER);

        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS signature");
            return;
        }

        let nt_headers =
            &*(buffer.as_ptr().add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS);

        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT signature");
            return;
        }

        /*
        File header:
            - Machine: The architecture type of the target machine.
            - NumberOfSections: The number of sections in the PE file.
            - TimeDateStamp: The time and date when the file was created.
            - PointerToSymbolTable and NumberOfSymbols: Used for debugging purposes, these fields are typically set to zero in modern PE files.
            - NumberOfSymbols: Number of symbols in the symbol table.
            - SizeOfOptionalHeader: The size of the optional header, which follows the file header.
            - Characteristics: A set of flags that indicate various attributes of the file, such as whether it's an executable, a DLL, or a system file, and whether it supports 32-bit or 64-bit architecture.
        */

        let file_header = nt_headers.FileHeader;
        println!("[+] File Header:");
        println!(
            "\t[i] File is: {}",
            if file_header.Characteristics & IMAGE_FILE_DLL != 0 {
                "DLL"
            } else if file_header.Characteristics & IMAGE_SUBSYSTEM_NATIVE != 0 {
                "SYS"
            } else {
                "EXE"
            }
        );
        println!(
            "\t[i] File Architecture: {}",
            if file_header.Machine == IMAGE_FILE_MACHINE_I386 {
                "x32"
            } else {
                "x64"
            }
        );
        println!("\t[i] Number of Sections: {}", file_header.NumberOfSections);
        println!(
            "\t[i] Size of Optional Header: {} bytes",
            file_header.SizeOfOptionalHeader
        );
        /*
        Optional header:
            - Magic: Specifies the type of the optional header.
            - MajorLinkerVersion: The major version number of the linker.
            - MinorLinkerVersion: The minor version number of the linker.
            - SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData: Sizes of code, initialized data, and uninitialized data sections.
            - AddressOfEntryPoint: The address of the entry point function.
            - BaseOfCode and BaseOfData: The base addresses of the code and data sections.
            - ImageBase: The preferred address of the first byte of the image when loaded into memory
            - MajorOperatingSystemVersion and MinorOperatingSystemVersion: The required operating system version.
            - MajorImageVersion and MinorImageVersion: The version of the image.
            - DataDirectory: An array of IMAGE_DATA_DIRECTORY structures that describe the location and size of various data directories, such as the import table, export table, resource table, etc.
        */

        let optional_header = nt_headers.OptionalHeader;

        if optional_header.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC {
            println!("[-] Invalid Optional Header magic");
            return;
        }

        println!("[+] Optional Header:");
        println!("\t[i] File Architecture : {}", if optional_header.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC { "x32" } else { "x64" });
        println!("\t[+] Size of Code : {}", optional_header.SizeOfCode);
        println!("\t[+] Address of Code Section : {:?}", buffer.as_ptr().add(optional_header.BaseOfCode as usize));
        println!("\t\t[RVA: 0x{:x}]", optional_header.BaseOfCode);
        println!("\t[+] Size of Initialized Data : {}", optional_header.SizeOfInitializedData);
        println!("\t[+] Size of Uninitialized Data : {}", optional_header.SizeOfUninitializedData);
        println!("\t[+] Preferable Mapping Address : 0x{:8x}", optional_header.ImageBase);
        println!("\t[+] Required Version : {}.{}", optional_header.MajorOperatingSystemVersion, optional_header.MinorOperatingSystemVersion);
        println!("\t[+] Address of Entry Point : {:?}", buffer.as_ptr().add(optional_header.AddressOfEntryPoint as usize));
        println!("\t\t[RVA: 0x{:x}]", optional_header.AddressOfEntryPoint);
        println!("\t[+] Size of the Image : {}", optional_header.SizeOfImage);
        println!("\t[+] File CheckSum : 0x{:8x}", optional_header.CheckSum);
        println!("\t[+] Number of entries in the DataDirectory : {}", optional_header.NumberOfRvaAndSizes);

        /*
        Data Directory:
            - VirtualAddress: The relative virtual address (RVA) of the data directory.
            - Size: The size of the data directory in bytes.

        predefined data directories:
            - IMAGE_DIRECTORY_ENTRY_EXPORT: The export table, which contains information about the functions and symbols that the PE file exports for use by other modules.
            - IMAGE_DIRECTORY_ENTRY_IMPORT: The import table, which contains information about the functions and symbols that the PE file imports from other modules.
            - IMAGE_DIRECTORY_ENTRY_RESOURCE: The resource table, which contains information about the resources (such as icons, dialogs, and strings) that are embedded in the PE file.
            - IMAGE_DIRECTORY_ENTRY_EXCEPTION: The exception table, which contains information about the exception handlers used by the PE file.
            - IMAGE_DIRECTORY_ENTRY_BASERELOC: The base relocation table, which contains information about the relocations that need to be applied when the PE file is loaded into memory at a different base address than its preferred ImageBase.
        */
        
        println!("[+] Data Directories");

        let export_data_dir = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        println!("\t[*] Export Directory At {:?} of size : {}", buffer.as_ptr().add(export_data_dir.VirtualAddress as usize), export_data_dir.Size);
        println!("\t\t[RVA: 0x{:x}]", export_data_dir.VirtualAddress);
        
        let import_data_dir = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];

        println!("\t[*] Export Directory At {:?} of size : {}", buffer.as_ptr().add(import_data_dir.VirtualAddress as usize), import_data_dir.Size);
        println!("\t\t[RVA: 0x{:x}]", import_data_dir.VirtualAddress);

        let resource_data_dir = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE as usize];

        println!("\t[*] Export Directory At {:?} of size : {}", buffer.as_ptr().add(resource_data_dir.VirtualAddress as usize), resource_data_dir.Size);
        println!("\t\t[RVA: 0x{:x}]", resource_data_dir.VirtualAddress);

        let exception_data_dir = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize];

        println!("\t[*] Export Directory At {:?} of size : {}", buffer.as_ptr().add(exception_data_dir.VirtualAddress as usize), exception_data_dir.Size);
        println!("\t\t[RVA: 0x{:x}]", exception_data_dir.VirtualAddress);

        let reloc_data_dir = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

        println!("\t[*] Export Directory At {:?} of size : {}", buffer.as_ptr().add(reloc_data_dir.VirtualAddress as usize), reloc_data_dir.Size);
        println!("\t\t[RVA: 0x{:x}]", reloc_data_dir.VirtualAddress);

        let tls_data_dir = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS as usize];

        println!("\t[*] Export Directory At {:?} of size : {}", buffer.as_ptr().add(tls_data_dir.VirtualAddress as usize), tls_data_dir.Size);
        println!("\t\t[RVA: 0x{:x}]", tls_data_dir.VirtualAddress);

        let iat_data_dir = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT as usize];

        println!("\t[*] Export Directory At {:?} of size : {}", buffer.as_ptr().add(iat_data_dir.VirtualAddress as usize), iat_data_dir.Size);
        println!("\t\t[RVA: 0x{:x}]", iat_data_dir.VirtualAddress);

        /*
        Export Directory:
            - Characteristics: Reserved, must be zero.
            - TimeDateStamp: The time and date when the export data was created.
            - MajorVersion and MinorVersion: The version of the export data.
            - Name: The RVA of the ASCII string that contains the name of the DLL.
            - Base: The starting ordinal number for exports in this directory. This is used to calculate the ordinal values for exported functions.
            - NumberOfFunctions: The total number of functions exported by the PE file.
            - NumberOfNames: The total number of named exports (functions that are exported by name rather than by ordinal).
            - AddressOfFunctions: The RVA of the array of function addresses (the export address table).
            - AddressOfNames: The RVA of the array of pointers to the names of the exported functions (the export name pointer table).
            - AddressOfNameOrdinals: The RVA of the array of ordinals corresponding to the named exports (the export ordinal table).
        */
        /* 
        let export_dir = buffer.as_ptr().add(export_data_dir.VirtualAddress as usize)
        as *const IMAGE_EXPORT_DIRECTORY;
        */

        /*
        Import Directory:
            - Characteristics: Reserved, must be zero.
            - OriginalFirstThunk: The RVA of the array of IMAGE_IMPORT_BY_NAME structures, which contain the names of the imported functions and their corresponding ordinals.
            - TimeDateStamp: The time and date when the import data was created.
            - ForwarderChain: The index of the first forwarder reference in the import address table
            - Name: The RVA of the ASCII string that contains the name of the DLL from which functions are imported.
            - FirstThunk: The RVA of the array of IMAGE_THUNK_DATA structures, which contain the addresses of the imported functions. When the PE file is loaded into memory, the loader replaces the
        */

        /*
        let import_desc = buffer.as_ptr().add(
            optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress
                as usize,
        ) as *const IMAGE_IMPORT_DESCRIPTOR;

        println!("[+] Number of sections: {}", file_header.NumberOfSections);
        */

        /*
        Section Headers:
            - Name: A null-terminated string that contains the name of the section (up to 8 characters).
            - VirtualAddress: The RVA of the section when loaded into memory.
            - SizeOfRawData: The size of the section's data in the PE file.
            - PointerToRelocations: The file offset to the beginning of the section's relocation entries (if any).
            - NumberOfRelocations: The number of relocation entries for the section.
            - Characteristics: A set of flags that indicate various attributes of the section, such as whether it contains code, initialized data, or uninitialized data, and whether it is readable, writable, or executable.
        */

        // let section_headers = &*(buffer.as_ptr().add(nt_headers as *const _ as usize - buffer.as_ptr() as usize + size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER);

        let section_headers = &*(buffer
            .as_ptr()
            .add(dos_header.e_lfanew as usize + size_of::<IMAGE_NT_HEADERS>())
            as *const IMAGE_SECTION_HEADER);

        println!("[+] Sections");

        for i in 0..file_header.NumberOfSections {
            let section = &*((section_headers as *const IMAGE_SECTION_HEADER).add(i as usize));
            let name = std::str::from_utf8(&section.Name)
                .unwrap_or("")
                .trim_matches(char::from(0));
            // println!(
            //     "[+] Section {}: Name: {}, VirtualAddress: 0x{:x}, SizeOfRawData: {:x} bytes",
            //     i + 1,
            //     name,
            //     section.VirtualAddress,
            //     section.SizeOfRawData
            // );
            println!("[#] {} ", name);
            println!("\tSize : {}", section.SizeOfRawData);
            println!("\tRVA : 0x{:x}", section.VirtualAddress);
            println!("\tAddress : {:?}", buffer.as_ptr().add(section.VirtualAddress as usize));
            println!("\tRelocations : {}", section.NumberOfRelocations);
            let perm_str = {
                let read = (section.Characteristics & IMAGE_SCN_MEM_READ) != 0;
                let write = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                let execute = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

                if execute && read && write {
                    "PAGE_EXECUTE_READWRITE"
                } else if execute && read {
                    "PAGE_EXECUTE_READ"
                } else if read && write {
                    "PAGE_READWRITE"
                } else if read {
                    "PAGE_READONLY"
                } else if execute {
                    "PAGE_EXECUTE"
                } else if write {
                    "PAGE_WRITECOPY"
                } else {
                    "NONE"
                }
            };

            println!("\tPermissions : {}", perm_str);
        }
    }
}
