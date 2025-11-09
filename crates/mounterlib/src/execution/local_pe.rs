use anyhow::{Context, Result};
use std::ffi::c_void;
use std::mem;
use std::ptr;
use windows::core::PCSTR;
use windows::Win32::Foundation::{BOOL, HINSTANCE};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_FILE_DLL, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
};
use windows::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
    IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG32,
    IMAGE_ORDINAL_FLAG64, IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH,
    IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW, IMAGE_TLS_DIRECTORY64, PIMAGE_TLS_CALLBACK,
};
use windows::Win32::System::WindowsProgramming::{IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64};

// Function pointer types
type ExeEntryPoint = unsafe extern "system" fn() -> BOOL;
type DllEntryPoint = unsafe extern "system" fn(HINSTANCE, u32, *mut c_void) -> BOOL;

// CRT Import Stubs - Global variables
static mut STUB_ENVIRON: *mut *mut i8 = ptr::null_mut();
static mut STUB_FMODE: i32 = 0;

/// Stub for __p__environ - returns pointer to environment variables
#[no_mangle]
unsafe extern "C" fn stub__p__environ() -> *mut *mut i8 {
    std::ptr::addr_of_mut!(STUB_ENVIRON) as *mut *mut i8
}

/// Stub for __p__fmode - returns pointer to file mode
#[no_mangle]
unsafe extern "C" fn stub__p__fmode() -> *mut i32 {
    std::ptr::addr_of_mut!(STUB_FMODE)
}

// Base relocation entry structure
#[repr(C)]
struct BaseRelocationEntry {
    data: u16,
}

impl BaseRelocationEntry {
    fn offset(&self) -> u16 {
        self.data & 0x0FFF
    }

    fn type_(&self) -> u16 {
        self.data >> 12
    }
}

/// Execute PE binary in memory (Local PE Injection)
pub fn inject_and_execute(pe_data: &[u8], args: &[String], verbose: bool) -> Result<()> {
    if verbose {
        println!("Starting Local PE Injection...");
    }

    validate_pe(pe_data, verbose)?;
    let is_64bit = is_pe64(pe_data)?;

    if verbose {
        println!(
            "Architecture: {}",
            if is_64bit { "64-bit" } else { "32-bit" }
        );
    }

    if is_64bit {
        execute_pe64(pe_data, args, verbose)
    } else {
        execute_pe32(pe_data, args, verbose)
    }
}

fn execute_pe32(pe_data: &[u8], _args: &[String], verbose: bool) -> Result<()> {
    let (_dos_header, nt_header) = get_headers32(pe_data)?;
    let is_dll = unsafe { (*nt_header).FileHeader.Characteristics.0 & IMAGE_FILE_DLL.0 != 0 };

    if verbose {
        println!("Type: {}", if is_dll { "DLL" } else { "EXE" });
        unsafe {
            println!("Image size: 0x{:X}", (*nt_header).OptionalHeader.SizeOfImage);
            println!("Entry point: 0x{:X}", (*nt_header).OptionalHeader.AddressOfEntryPoint);
        }
    }

    if verbose {
        println!("Allocating memory...");
    }
    let image_base = allocate_image_memory32(nt_header, verbose)?;

    if verbose {
        println!("Copying headers...");
    }
    copy_headers32(pe_data, image_base, nt_header)?;

    if verbose {
        println!("Copying sections...");
    }
    copy_sections32(pe_data, image_base, nt_header, verbose)?;

    if verbose {
        println!("Resolving imports...");
    }
    fix_imports32(image_base, nt_header, verbose)?;

    if verbose {
        println!("Applying relocations...");
    }
    fix_relocations32(image_base, nt_header, verbose)?;

    if verbose {
        println!("Fixing memory protections...");
    }
    fix_memory_protections32(image_base, nt_header)?;

    if verbose {
        println!("Executing TLS callbacks...");
    }
    execute_tls_callbacks32(image_base, nt_header, verbose)?;

    if verbose {
        println!("Executing entry point...");
    }
    execute_entrypoint32(image_base, nt_header, is_dll)?;

    Ok(())
}

fn execute_pe64(pe_data: &[u8], _args: &[String], verbose: bool) -> Result<()> {
    let (_dos_header, nt_header) = get_headers64(pe_data)?;
    let is_dll = unsafe { (*nt_header).FileHeader.Characteristics.0 & IMAGE_FILE_DLL.0 != 0 };

    if verbose {
        println!("Type: {}", if is_dll { "DLL" } else { "EXE" });
    }

    if verbose {
        println!("Allocating memory...");
    }
    let image_base = allocate_image_memory64(nt_header, verbose)?;

    if verbose {
        println!("Copying headers...");
    }
    copy_headers64(pe_data, image_base, nt_header, verbose)?;

    if verbose {
        println!("Copying sections...");
    }
    copy_sections64(pe_data, image_base, nt_header, verbose)?;

    if verbose {
        println!("Resolving imports...");
    }
    fix_imports64(image_base, nt_header, verbose)?;

    if verbose {
        println!("Applying relocations...");
    }
    fix_relocations64(image_base, nt_header, verbose)?;

    if verbose {
        println!("Fixing memory protections...");
    }
    fix_memory_protections64(image_base, nt_header, verbose)?;

    if verbose {
        println!("Executing TLS callbacks...");
    }
    execute_tls_callbacks64(image_base, nt_header, verbose)?;

    if verbose {
        println!("Executing entry point...");
    }
    execute_entrypoint64(image_base, nt_header, is_dll, verbose)?;

    if verbose {
        println!("Execution completed");
    }

    Ok(())
}

fn is_pe64(pe_data: &[u8]) -> Result<bool> {
    unsafe {
        let dos_header = pe_data.as_ptr() as *const IMAGE_DOS_HEADER;
        let nt_header =
            (dos_header as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS32;

        // Read the Magic field from OptionalHeader
        let magic = (*nt_header).OptionalHeader.Magic;

        // 0x10b = PE32 (32-bit), 0x20b = PE32+ (64-bit)
        Ok(magic.0 == 0x20b)
    }
}

fn validate_pe(pe_data: &[u8], verbose: bool) -> Result<()> {
    if pe_data.len() < mem::size_of::<IMAGE_DOS_HEADER>() {
        anyhow::bail!("File too small to be a valid PE");
    }

    unsafe {
        let dos_header = pe_data.as_ptr() as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            anyhow::bail!("Invalid DOS signature (expected: MZ)");
        }

        let nt_header =
            (dos_header as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            anyhow::bail!("Invalid NT signature (expected: PE)");
        }
    }

    if verbose {
        println!("Valid PE");
    }

    Ok(())
}

fn get_headers32(pe_data: &[u8]) -> Result<(*const IMAGE_DOS_HEADER, *mut IMAGE_NT_HEADERS32)> {
    unsafe {
        let dos_header = pe_data.as_ptr() as *const IMAGE_DOS_HEADER;
        let nt_header =
            (dos_header as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32;
        Ok((dos_header, nt_header))
    }
}

fn allocate_image_memory32(
    nt_header: *mut IMAGE_NT_HEADERS32,
    verbose: bool,
) -> Result<*mut c_void> {
    unsafe {
        let size = (*nt_header).OptionalHeader.SizeOfImage as usize;
        let preferred_base = (*nt_header).OptionalHeader.ImageBase as usize;

        if verbose {
            println!("  Preferred base: 0x{:X}", preferred_base);
        }

        // Try to allocate at preferred base first (important for PEs without relocations)
        let mut address = VirtualAlloc(
            Some(preferred_base as *const _),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if address.is_null() {
            if verbose {
                println!(
                    "  Could not allocate at preferred base, trying alternate address..."
                );
            }
            // If preferred base fails, let OS choose
            address = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }

        if address.is_null() {
            anyhow::bail!("VirtualAlloc failed to allocate memory");
        }

        if verbose {
            println!("  Memory allocated at: {:p}", address);
            if address as usize == preferred_base {
                println!("  Loaded at preferred base - no relocations needed");
            }
        }

        Ok(address)
    }
}

fn copy_headers32(
    pe_data: &[u8],
    image_base: *mut c_void,
    nt_header: *mut IMAGE_NT_HEADERS32,
) -> Result<()> {
    unsafe {
        let headers_size = (*nt_header).OptionalHeader.SizeOfHeaders as usize;
        ptr::copy_nonoverlapping(pe_data.as_ptr(), image_base as *mut u8, headers_size);
    }
    Ok(())
}

fn copy_sections32(
    pe_data: &[u8],
    image_base: *mut c_void,
    _nt_header: *mut IMAGE_NT_HEADERS32,
    verbose: bool,
) -> Result<()> {
    unsafe {
        // Get headers from the allocated memory, not the original buffer
        let dos_header_in_memory = image_base as *const IMAGE_DOS_HEADER;
        let nt_header_in_memory = (image_base as usize + (*dos_header_in_memory).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS32;

        let num_sections = (*nt_header_in_memory).FileHeader.NumberOfSections;
        let mut section_header = (nt_header_in_memory as usize
            + mem::size_of::<IMAGE_NT_HEADERS32>())
            as *mut IMAGE_SECTION_HEADER;

        for i in 0..num_sections {
            let section = &*section_header;

            if verbose {
                let name = String::from_utf8_lossy(&section.Name);
                println!(
                    "  Section {}: {} (VA: 0x{:X}, Size: 0x{:X})",
                    i,
                    name.trim_end_matches('\0'),
                    section.VirtualAddress,
                    section.SizeOfRawData
                );
            }

            if section.SizeOfRawData > 0 && section.PointerToRawData > 0 {
                let dst = (image_base as usize + section.VirtualAddress as usize) as *mut u8;
                let start = section.PointerToRawData as usize;
                let end = start + section.SizeOfRawData as usize;

                if end <= pe_data.len() {
                    let src = &pe_data[start..end];
                    ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
                } else {
                    anyhow::bail!("Section out of buffer bounds");
                }
            }

            section_header = section_header.add(1);
        }
    }

    Ok(())
}

fn fix_imports32(
    image_base: *mut c_void,
    nt_header: *mut IMAGE_NT_HEADERS32,
    verbose: bool,
) -> Result<()> {
    unsafe {
        let import_dir =
            (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize];

        if import_dir.Size == 0 || import_dir.VirtualAddress == 0 {
            if verbose {
                println!("  (No imports)");
            }
            return Ok(());
        }

        let import_descriptor = (image_base as usize + import_dir.VirtualAddress as usize)
            as *mut IMAGE_IMPORT_DESCRIPTOR;
        let mut current_import = import_descriptor;

        while (*current_import).Name != 0 {
            let dll_name = (image_base as usize + (*current_import).Name as usize) as *const i8;
            let dll_name_str = std::ffi::CStr::from_ptr(dll_name);

            if verbose {
                println!("  Loading: {:?}", dll_name_str);
            }

            let h_module = match LoadLibraryA(PCSTR(dll_name as *const u8)) {
                Ok(module) => module,
                Err(_) => {
                    anyhow::bail!("Failed to load DLL: {:?}", dll_name_str);
                }
            };

            // Resolve imports
            let original_first_thunk = (*current_import).Anonymous.OriginalFirstThunk;
            let first_thunk = (*current_import).FirstThunk;

            let mut thunk_offset = 0isize;
            loop {
                let original_thunk =
                    (image_base as usize + original_first_thunk as usize + thunk_offset as usize)
                        as *const IMAGE_THUNK_DATA32;
                let thunk = (image_base as usize + first_thunk as usize + thunk_offset as usize)
                    as *mut IMAGE_THUNK_DATA32;

                if (*original_thunk).u1.Function == 0 {
                    break;
                }

                let func_address = if (*original_thunk).u1.Ordinal & IMAGE_ORDINAL_FLAG32 != 0 {
                    // Import by ordinal
                    let ordinal = (*original_thunk).u1.Ordinal & 0xFFFF;
                    GetProcAddress(h_module, PCSTR(ordinal as *const u8))
                } else {
                    // Import by name
                    let import_by_name = (image_base as usize
                        + (*original_thunk).u1.AddressOfData as usize)
                        as *const IMAGE_IMPORT_BY_NAME;
                    let func_name = (*import_by_name).Name.as_ptr() as *const i8;
                    GetProcAddress(h_module, PCSTR(func_name as *const u8))
                };

                match func_address {
                    Some(addr) => {
                        (*thunk).u1.Function = addr as usize as u32;
                    }
                    None => {
                        // Try to provide a stub for known CRT functions
                        let func_name = if (*original_thunk).u1.Ordinal & IMAGE_ORDINAL_FLAG32 != 0
                        {
                            format!("Ordinal #{}", (*original_thunk).u1.Ordinal & 0xFFFF)
                        } else {
                            let import_by_name = (image_base as usize
                                + (*original_thunk).u1.AddressOfData as usize)
                                as *const IMAGE_IMPORT_BY_NAME;
                            let name = (*import_by_name).Name.as_ptr() as *const i8;
                            format!("{:?}", std::ffi::CStr::from_ptr(name))
                        };

                        // Check if this is a known CRT function we can stub
                        let stub_addr = if func_name.contains("__p__environ") {
                            Some(stub__p__environ as *const () as u32)
                        } else if func_name.contains("__p__fmode") {
                            Some(stub__p__fmode as *const () as u32)
                        } else {
                            None
                        };

                        if let Some(addr) = stub_addr {
                            (*thunk).u1.Function = addr;
                            if verbose {
                                println!(
                                    "  Using stub for import: {} from {:?}",
                                    func_name, dll_name_str
                                );
                            }
                        } else {
                            if verbose {
                                println!(
                                    "  Could not resolve import: {} from {:?}",
                                    func_name, dll_name_str
                                );
                            }
                            // Set to null and continue - some imports may be optional
                            (*thunk).u1.Function = 0;
                        }
                    }
                }

                thunk_offset += mem::size_of::<IMAGE_THUNK_DATA32>() as isize;
            }

            current_import = current_import.add(1);
        }
    }

    Ok(())
}

fn fix_relocations32(
    image_base: *mut c_void,
    _nt_header: *mut IMAGE_NT_HEADERS32,
    verbose: bool,
) -> Result<()> {
    unsafe {
        // Read headers from allocated memory, not original buffer
        let dos_header_in_memory = image_base as *const IMAGE_DOS_HEADER;
        let nt_header_in_memory = (image_base as usize + (*dos_header_in_memory).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS32;

        if verbose {
            let e_lfanew_val = (*dos_header_in_memory).e_lfanew;
            let image_base_val = (*nt_header_in_memory).OptionalHeader.ImageBase;
            println!("  Debug: Image base in memory: {:p}", image_base);
            println!("  Debug: e_lfanew: 0x{:X}", e_lfanew_val);
            println!("  Debug: NT headers at: {:p}", nt_header_in_memory);
            println!("  Debug: ImageBase from header: 0x{:X}", image_base_val);
        }

        let reloc_dir = (*nt_header_in_memory).OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize];

        if verbose {
            println!(
                "  Debug: Reloc dir VA: 0x{:X}, Size: 0x{:X}",
                reloc_dir.VirtualAddress, reloc_dir.Size
            );
        }

        if reloc_dir.Size == 0 || reloc_dir.VirtualAddress == 0 {
            if verbose {
                println!("  (No relocations in PE)");
            }
            return Ok(());
        }

        let delta = image_base as isize - (*nt_header_in_memory).OptionalHeader.ImageBase as isize;

        if delta == 0 {
            if verbose {
                println!("  Loaded at preferred base, no relocations needed");
            }
            return Ok(());
        }

        if verbose {
            println!("  Delta: 0x{:X}", delta);
            println!("  Relocation entries: {} bytes", reloc_dir.Size);
        }

        let mut base_relocation =
            (image_base as usize + reloc_dir.VirtualAddress as usize) as *mut IMAGE_BASE_RELOCATION;

        while (*base_relocation).VirtualAddress != 0 {
            let mut entry = base_relocation.offset(1) as *mut BaseRelocationEntry;
            let block_end = (base_relocation as *mut u8)
                .offset((*base_relocation).SizeOfBlock as isize)
                as *mut BaseRelocationEntry;

            while entry < block_end {
                let reloc_type = (*entry).type_();
                let offset = (*entry).offset() as u32;
                let target = (image_base as usize
                    + (*base_relocation).VirtualAddress as usize
                    + offset as usize) as *mut u8;

                match reloc_type as u32 {
                    IMAGE_REL_BASED_DIR64 => {
                        let value = (target as *mut isize).read_unaligned();
                        (target as *mut isize).write_unaligned(value + delta);
                    }
                    IMAGE_REL_BASED_HIGHLOW => {
                        let value = (target as *mut u32).read_unaligned();
                        (target as *mut u32).write_unaligned(value.wrapping_add(delta as u32));
                    }
                    IMAGE_REL_BASED_HIGH => {
                        let value = (target as *mut u16).read_unaligned() as u32;
                        (target as *mut u16).write_unaligned(
                            value.wrapping_add((delta as u32 >> 16) & 0xFFFF) as u16,
                        );
                    }
                    IMAGE_REL_BASED_LOW => {
                        let value = (target as *mut u16).read_unaligned() as u32;
                        (target as *mut u16)
                            .write_unaligned(value.wrapping_add(delta as u32 & 0xFFFF) as u16);
                    }
                    IMAGE_REL_BASED_ABSOLUTE => {}
                    _ => {
                        if verbose {
                            println!("  Unknown relocation type: {}", reloc_type);
                        }
                    }
                }

                entry = entry.add(1);
            }

            base_relocation = entry as *mut IMAGE_BASE_RELOCATION;
        }
    }

    Ok(())
}

fn fix_memory_protections32(
    image_base: *mut c_void,
    _nt_header: *mut IMAGE_NT_HEADERS32
) -> Result<()> {
    unsafe {
        // Get headers from the allocated memory
        let dos_header_in_memory = image_base as *const IMAGE_DOS_HEADER;
        let nt_header_in_memory = (image_base as usize + (*dos_header_in_memory).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS32;

        let num_sections = (*nt_header_in_memory).FileHeader.NumberOfSections;
        let mut section_header = (nt_header_in_memory as usize
            + mem::size_of::<IMAGE_NT_HEADERS32>())
            as *mut IMAGE_SECTION_HEADER;

        for _ in 0..num_sections {
            let section = &*section_header;
            let characteristics = section.Characteristics;

            let protection = if characteristics.0 & 0x20000000 != 0 {
                // IMAGE_SCN_MEM_EXECUTE
                if characteristics.0 & 0x80000000 != 0 {
                    // IMAGE_SCN_MEM_WRITE
                    PAGE_EXECUTE_READWRITE
                } else {
                    PAGE_EXECUTE_READ
                }
            } else if characteristics.0 & 0x80000000 != 0 {
                // IMAGE_SCN_MEM_WRITE
                PAGE_READWRITE
            } else {
                PAGE_READONLY
            };

            let address = (image_base as usize + section.VirtualAddress as usize) as *const c_void;
            let size = section.Misc.VirtualSize as usize;

            if size > 0 {
                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                VirtualProtect(address, size, protection, &mut old_protect)
                    .context("Failed to change section protection")?;
            }

            section_header = section_header.add(1);
        }
    }

    Ok(())
}

// ============================================================================
// 64-bit PE Functions
// ============================================================================

fn get_headers64(pe_data: &[u8]) -> Result<(*const IMAGE_DOS_HEADER, *mut IMAGE_NT_HEADERS64)> {
    unsafe {
        let dos_header = pe_data.as_ptr() as *const IMAGE_DOS_HEADER;
        let nt_header =
            (dos_header as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
        Ok((dos_header, nt_header))
    }
}

fn allocate_image_memory64(
    nt_header: *mut IMAGE_NT_HEADERS64,
    verbose: bool,
) -> Result<*mut c_void> {
    unsafe {
        let size = (*nt_header).OptionalHeader.SizeOfImage as usize;
        let preferred_base = (*nt_header).OptionalHeader.ImageBase as usize;

        if verbose {
            println!("  Preferred base: 0x{:X}", preferred_base);
        }

        // Try to allocate at preferred base first (important for PEs without relocations)
        let mut address = VirtualAlloc(
            Some(preferred_base as *const _),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if address.is_null() {
            if verbose {
                println!(
                    "  Could not allocate at preferred base, trying alternate address..."
                );
            }
            // If preferred base fails, let OS choose
            address = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }

        if address.is_null() {
            anyhow::bail!("VirtualAlloc failed to allocate memory");
        }

        if verbose {
            println!("  Memory allocated at: {:p}", address);
            if address as usize == preferred_base {
                println!("  Loaded at preferred base - no relocations needed");
            }
        }

        Ok(address)
    }
}

fn copy_headers64(
    pe_data: &[u8],
    image_base: *mut c_void,
    nt_header: *mut IMAGE_NT_HEADERS64,
    _verbose: bool,
) -> Result<()> {
    unsafe {
        let headers_size = (*nt_header).OptionalHeader.SizeOfHeaders as usize;
        ptr::copy_nonoverlapping(pe_data.as_ptr(), image_base as *mut u8, headers_size);
    }
    Ok(())
}

fn copy_sections64(
    pe_data: &[u8],
    image_base: *mut c_void,
    nt_header: *mut IMAGE_NT_HEADERS64,
    verbose: bool,
) -> Result<()> {
    unsafe {
        let section_header = (nt_header as usize + mem::size_of::<IMAGE_NT_HEADERS64>())
            as *mut IMAGE_SECTION_HEADER;
        let num_sections = (*nt_header).FileHeader.NumberOfSections;

        for i in 0..num_sections {
            let section = section_header.add(i as usize);
            let section_name = {
                // Section names are 8 bytes, may not be null-terminated
                let name_bytes = &(*section).Name;
                let name_str = std::str::from_utf8(name_bytes)
                    .unwrap_or("")
                    .trim_end_matches('\0');
                name_str
            };

            if verbose {
                println!(
                    "  Copying section: {} (size: {}, RVA: 0x{:X})",
                    section_name,
                    (*section).SizeOfRawData,
                    (*section).VirtualAddress
                );
            }

            if (*section).SizeOfRawData > 0 {
                let dest = (image_base as usize + (*section).VirtualAddress as usize) as *mut u8;
                let src_offset = (*section).PointerToRawData as usize;
                let size = (*section).SizeOfRawData as usize;

                if src_offset + size <= pe_data.len() {
                    ptr::copy_nonoverlapping(pe_data.as_ptr().add(src_offset), dest, size);
                } else {
                    anyhow::bail!("Section out of file bounds");
                }
            }
        }
    }

    Ok(())
}

fn fix_imports64(
    image_base: *mut c_void,
    nt_header: *mut IMAGE_NT_HEADERS64,
    verbose: bool,
) -> Result<()> {
    unsafe {
        let import_dir =
            (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize];

        if import_dir.Size == 0 || import_dir.VirtualAddress == 0 {
            if verbose {
                println!("  (No imports)");
            }
            return Ok(());
        }

        let import_descriptor = (image_base as usize + import_dir.VirtualAddress as usize)
            as *mut IMAGE_IMPORT_DESCRIPTOR;
        let mut current_import = import_descriptor;

        while (*current_import).Name != 0 {
            let dll_name = (image_base as usize + (*current_import).Name as usize) as *const i8;
            let dll_name_str = std::ffi::CStr::from_ptr(dll_name);

            if verbose {
                println!("  Loading: {:?}", dll_name_str);
            }

            let h_module = match LoadLibraryA(PCSTR(dll_name as *const u8)) {
                Ok(module) => module,
                Err(_) => {
                    anyhow::bail!("Failed to load DLL: {:?}", dll_name_str);
                }
            };

            // Resolve imports
            let original_first_thunk = (*current_import).Anonymous.OriginalFirstThunk;
            let first_thunk = (*current_import).FirstThunk;

            let mut thunk_offset = 0isize;
            loop {
                let original_thunk =
                    (image_base as usize + original_first_thunk as usize + thunk_offset as usize)
                        as *const IMAGE_THUNK_DATA64;
                let thunk = (image_base as usize + first_thunk as usize + thunk_offset as usize)
                    as *mut IMAGE_THUNK_DATA64;

                if (*original_thunk).u1.Function == 0 {
                    break;
                }

                let func_address = if (*original_thunk).u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0 {
                    // Import by ordinal
                    let ordinal = (*original_thunk).u1.Ordinal & 0xFFFF;
                    GetProcAddress(h_module, PCSTR(ordinal as *const u8))
                } else {
                    // Import by name
                    let import_by_name = (image_base as usize
                        + (*original_thunk).u1.AddressOfData as usize)
                        as *const IMAGE_IMPORT_BY_NAME;
                    let func_name = (*import_by_name).Name.as_ptr() as *const i8;
                    GetProcAddress(h_module, PCSTR(func_name as *const u8))
                };

                match func_address {
                    Some(addr) => {
                        (*thunk).u1.Function = addr as usize as u64;
                    }
                    None => {
                        // Try to provide a stub for known CRT functions
                        let func_name = if (*original_thunk).u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0
                        {
                            format!("Ordinal #{}", (*original_thunk).u1.Ordinal & 0xFFFF)
                        } else {
                            let import_by_name = (image_base as usize
                                + (*original_thunk).u1.AddressOfData as usize)
                                as *const IMAGE_IMPORT_BY_NAME;
                            let name = (*import_by_name).Name.as_ptr() as *const i8;
                            format!("{:?}", std::ffi::CStr::from_ptr(name))
                        };

                        // Check if this is a known CRT function we can stub
                        let stub_addr = if func_name.contains("__p__environ") {
                            Some(stub__p__environ as *const () as u64)
                        } else if func_name.contains("__p__fmode") {
                            Some(stub__p__fmode as *const () as u64)
                        } else {
                            None
                        };

                        if let Some(addr) = stub_addr {
                            (*thunk).u1.Function = addr;
                            if verbose {
                                println!(
                                    "  Using stub for import: {} from {:?}",
                                    func_name, dll_name_str
                                );
                            }
                        } else {
                            if verbose {
                                println!(
                                    "  Could not resolve import: {} from {:?}",
                                    func_name, dll_name_str
                                );
                            }
                            // Set to null and continue - some imports may be optional
                            (*thunk).u1.Function = 0;
                        }
                    }
                }

                thunk_offset += mem::size_of::<IMAGE_THUNK_DATA64>() as isize;
            }

            current_import = current_import.add(1);
        }
    }

    Ok(())
}

fn fix_relocations64(
    image_base: *mut c_void,
    nt_header: *mut IMAGE_NT_HEADERS64,
    verbose: bool,
) -> Result<()> {
    unsafe {
        let reloc_dir =
            (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize];

        if reloc_dir.Size == 0 || reloc_dir.VirtualAddress == 0 {
            if verbose {
                println!("  (No relocations - must be at preferred base)");
            }
            return Ok(());
        }

        let preferred_base = (*nt_header).OptionalHeader.ImageBase as isize;
        let actual_base = image_base as isize;
        let delta = actual_base - preferred_base;

        if delta == 0 {
            if verbose {
                println!("  Loaded at preferred base - no relocations needed");
            }
            return Ok(());
        }

        if verbose {
            println!("    Delta: 0x{:X}", delta);
        }

        let mut reloc_block =
            (image_base as usize + reloc_dir.VirtualAddress as usize) as *mut IMAGE_BASE_RELOCATION;

        while (*reloc_block).VirtualAddress != 0 {
            let block_size = (*reloc_block).SizeOfBlock as usize;
            let num_entries =
                (block_size - mem::size_of::<IMAGE_BASE_RELOCATION>()) / mem::size_of::<u16>();

            let entries = (reloc_block as usize + mem::size_of::<IMAGE_BASE_RELOCATION>())
                as *const BaseRelocationEntry;

            for i in 0..num_entries {
                let entry = &*entries.add(i);
                let entry_type = entry.type_();
                let entry_offset = entry.offset();

                let target_address = (image_base as usize
                    + (*reloc_block).VirtualAddress as usize
                    + entry_offset as usize) as *mut isize;

                match entry_type as u32 {
                    IMAGE_REL_BASED_ABSOLUTE => {
                        // Skip, no relocation needed
                    }
                    IMAGE_REL_BASED_DIR64 => {
                        // 64-bit relocation
                        *target_address += delta;
                    }
                    IMAGE_REL_BASED_HIGHLOW => {
                        // 32-bit relocation (rarely used in 64-bit, but possible)
                        let target_32 = target_address as *mut u32;
                        *target_32 = (*target_32 as isize + delta) as u32;
                    }
                    IMAGE_REL_BASED_HIGH => {
                        // High 16 bits
                        let target_16 = target_address as *mut u16;
                        *target_16 = (*target_16 as isize + (delta >> 16)) as u16;
                    }
                    IMAGE_REL_BASED_LOW => {
                        // Low 16 bits
                        let target_16 = target_address as *mut u16;
                        *target_16 = (*target_16 as isize + (delta & 0xFFFF)) as u16;
                    }
                    _ => {
                        if verbose {
                            println!("    ⚠️  Unknown relocation type: {}", entry_type);
                        }
                    }
                }
            }

            reloc_block = (reloc_block as usize + block_size) as *mut IMAGE_BASE_RELOCATION;
        }
    }

    Ok(())
}

fn fix_memory_protections64(
    image_base: *mut c_void,
    nt_header: *mut IMAGE_NT_HEADERS64,
    verbose: bool,
) -> Result<()> {
    unsafe {
        let section_header = (nt_header as usize + mem::size_of::<IMAGE_NT_HEADERS64>())
            as *mut IMAGE_SECTION_HEADER;
        let num_sections = (*nt_header).FileHeader.NumberOfSections;

        if verbose {
            println!(
                "  Fixing protections for {} sections...",
                num_sections
            );
        }

        for i in 0..num_sections {
            let section = section_header.add(i as usize);
            let characteristics = (*section).Characteristics;

            let protection = if characteristics.0 & 0x20000000 != 0 {
                // IMAGE_SCN_MEM_EXECUTE
                if characteristics.0 & 0x80000000 != 0 {
                    // IMAGE_SCN_MEM_WRITE
                    PAGE_EXECUTE_READWRITE
                } else {
                    PAGE_EXECUTE_READ
                }
            } else if characteristics.0 & 0x80000000 != 0 {
                // IMAGE_SCN_MEM_WRITE
                PAGE_READWRITE
            } else {
                PAGE_READONLY
            };

            let address =
                (image_base as usize + (*section).VirtualAddress as usize) as *const c_void;
            let size = (*section).Misc.VirtualSize as usize;

            if size > 0 {
                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                VirtualProtect(address, size, protection, &mut old_protect)
                    .with_context(|| format!("Failed to change protection for section {}", i))?;
            }
        }
    }

    Ok(())
}

fn execute_tls_callbacks64(
    image_base: *mut c_void,
    nt_header: *mut IMAGE_NT_HEADERS64,
    verbose: bool,
) -> Result<()> {
    unsafe {
        let tls_dir =
            (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS.0 as usize];

        if tls_dir.Size == 0 || tls_dir.VirtualAddress == 0 {
            if verbose {
                println!("  (No TLS callbacks)");
            }
            return Ok(());
        }

        let tls_directory =
            (image_base as usize + tls_dir.VirtualAddress as usize) as *const IMAGE_TLS_DIRECTORY64;

        let callbacks_address = (*tls_directory).AddressOfCallBacks as *const PIMAGE_TLS_CALLBACK;

        if !callbacks_address.is_null() {
            let mut i = 0;
            while let Some(callback) = *callbacks_address.add(i) {
                if verbose {
                    println!("  Executing TLS callback #{}", i);
                }
                callback(image_base, DLL_PROCESS_ATTACH, ptr::null_mut());
                i += 1;
            }
        }
    }

    Ok(())
}

fn execute_entrypoint64(
    image_base: *mut c_void,
    nt_header: *mut IMAGE_NT_HEADERS64,
    is_dll: bool,
    _verbose: bool,
) -> Result<()> {
    unsafe {
        let entry_point = (image_base as usize
            + (*nt_header).OptionalHeader.AddressOfEntryPoint as usize)
            as *const c_void;

        if is_dll {
            let dll_main: DllEntryPoint = mem::transmute(entry_point);
            dll_main(
                HINSTANCE(image_base as isize),
                DLL_PROCESS_ATTACH,
                ptr::null_mut(),
            );
        } else {
            let exe_main: ExeEntryPoint = mem::transmute(entry_point);
            exe_main();
        }
    }

    Ok(())
}

fn execute_tls_callbacks32(
    image_base: *mut c_void,
    nt_header: *mut IMAGE_NT_HEADERS32,
    verbose: bool,
) -> Result<()> {
    unsafe {
        let tls_dir =
            (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS.0 as usize];

        if tls_dir.Size == 0 || tls_dir.VirtualAddress == 0 {
            return Ok(());
        }

        if verbose {
            println!("  Executing TLS callbacks...");
        }

        let tls_directory =
            (image_base as usize + tls_dir.VirtualAddress as usize) as *const IMAGE_TLS_DIRECTORY64;
        let callback_array = (*tls_directory).AddressOfCallBacks as *const PIMAGE_TLS_CALLBACK;

        let mut i = 0;
        while let Some(callback) = *callback_array.offset(i) {
            callback(image_base, DLL_PROCESS_ATTACH, ptr::null_mut());
            i += 1;
        }
    }

    Ok(())
}

fn execute_entrypoint32(
    image_base: *mut c_void,
    nt_header: *mut IMAGE_NT_HEADERS32,
    is_dll: bool,
) -> Result<()> {
    // SAFETY: The entry point is a valid function pointer.
    unsafe {
        let entry_point = (image_base as usize
            + (*nt_header).OptionalHeader.AddressOfEntryPoint as usize)
            as *const c_void;

        if is_dll {
            let dll_main: DllEntryPoint = mem::transmute(entry_point);
            dll_main(
                HINSTANCE(image_base as isize),
                DLL_PROCESS_ATTACH,
                ptr::null_mut(),
            );
        } else {
            let exe_main: ExeEntryPoint = mem::transmute(entry_point);
            exe_main();
        }
    }

    Ok(())
}
