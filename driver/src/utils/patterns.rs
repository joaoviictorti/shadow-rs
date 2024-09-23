use {
    obfstr::obfstr,
    super::{
        address::get_module_base_address, 
        InitializeObjectAttributes,
    },
    core::{
        ffi::{c_void, CStr}, mem::{size_of, zeroed}, 
        ptr::{null_mut, read}, slice::from_raw_parts
    },
    wdk_sys::{
        ntddk::{
            ZwClose, ZwMapViewOfSection, ZwOpenSection, 
            ZwUnmapViewOfSection
        }, 
        LARGE_INTEGER, OBJ_CASE_INSENSITIVE, PAGE_READONLY, SECTION_MAP_READ, 
        SECTION_QUERY, _SECTION_INHERIT::ViewUnmap, NT_SUCCESS
    },
    winapi::um::winnt::{
        IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, 
        IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER
    },
};

///
/// 
/// 
/// 
fn slice_to_number<T, const N: usize>(slice: &[u8], func: fn([u8; N]) -> T) -> Result<T, &'static str> {
    if slice.len() != N {
        return Err("Slice length mismatch");
    }

    // Converts the slice to an array of N bytes
    let array: [u8; N] = slice.try_into().map_err(|_| "Slice length mismatch")?;

    // Converts the byte array to the desired type
    Ok(func(array))
}

/// Scans memory for a specific pattern of bytes in a specific section.
/// 
/// # Parameters
/// - `base_addr`: The base address (in `usize` format) from which the scan should start.
/// - `section_name`: The name of the section to scan. This string must match the name of the section you want to scan.
/// - `pattern`: A slice of bytes (`&[u8]`) that represents the pattern you are searching for in memory.
/// 
/// # Returns
/// - `Option<*const u8>`: The address of the target function if found.
/// 
pub unsafe fn scan_for_pattern<T, const N: usize>(
    function_address: *mut c_void,
    pattern: &[u8],
    offset: usize,
    final_offset: isize,
    size: usize,
    func: fn([u8; N]) -> T,
) -> Option<*mut u8> 
where
    T: Into<i64>,
{
    let function_bytes = from_raw_parts(function_address as *const u8, size);

    if let Some(x) = function_bytes.windows(pattern.len()).position(|x| x == pattern) {
        let position = x + offset;
        let offset: T = slice_to_number(&function_bytes[position..position + N], func).ok()?;

        let address = function_address.cast::<u8>().offset(x as isize);
        let next_address = address.offset(final_offset);
        Some(next_address.offset(offset.into() as isize))
    } else {
        None
    }
}

/// Finds the address of a specified Zw function.
/// 
/// # Parameters
/// - `name`: The name of the Zw function to find.
///
/// # Returns
/// - `Option<usize>`: The address of the Zw function if found, or `None` if an error occurs or the function is not found.
/// 
pub unsafe fn find_zw_function(name: &str) -> Option<usize> {
    let ssn = get_syscall_index(name)?;
    let ntoskrnl_addr = get_module_base_address(obfstr!("ntoskrnl.exe"))?;

    let ssn_bytes = ssn.to_le_bytes();
    let pattern: [u8; 30] = [
        0x48, 0x8B, 0xC4,            // mov rax, rsp
        0xFA,                        // cli
        0x48, 0x83, 0xEC, 0x10,      // sub rsp, 10h
        0x50,                        // push rax
        0x9C,                        // pushfq
        0x6A, 0x10,                  // push 10h
        0x48, 0x8D, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, // lea rax, KiServiceLinkage
        0x50,                        // push rax
        0xB8, ssn_bytes[0], ssn_bytes[1], 0xCC, 0xCC, // mov eax, <SSN>
        0xE9, 0xCC, 0xCC, 0xCC, 0xCC // jmp KiServiceInternal
    ];
    
    let dos_header = ntoskrnl_addr as *const IMAGE_DOS_HEADER;
    let nt_header = (ntoskrnl_addr as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let section_header = (nt_header as usize + size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;

    for i in 0..(*nt_header).FileHeader.NumberOfSections as usize {
        let section = (*section_header.add(i)).Name;
        let name = core::str::from_utf8(&section).unwrap().trim_matches('\0');
        
        if name == obfstr!(".text") {
            let text_start = ntoskrnl_addr as usize + (*section_header.add(i)).VirtualAddress as usize;
            let text_end = text_start + *(*section_header.add(i)).Misc.VirtualSize() as usize;
            let data = core::slice::from_raw_parts(text_start as *const u8, text_end - text_start);

            if let Some(offset) = data.windows(pattern.len())
                .position(|window| {
                    window.iter().zip(&pattern).all(|(d, p)| *p == 0xCC || *d == *p)
                }) {
                
                return Some(text_start + offset);
            }
        }
    }

    None
}

/// Retrieves the syscall index for a given function name.
///
/// # Parameters
/// - `function_name`: The name of the function to retrieve the syscall index for.
///
/// # Returns
/// - `Option<u16>`: The syscall index if found, or `None` if an error occurs or the function is not found.
/// 
pub unsafe fn get_syscall_index(function_name: &str) -> Option<u16> {
    let mut section_handle = null_mut();
    let dll = crate::utils::uni::str_to_unicode(obfstr!("\\KnownDlls\\ntdll.dll"));
    let mut obj_attr = InitializeObjectAttributes(Some(&mut dll.to_unicode()), OBJ_CASE_INSENSITIVE, None, None, None);
    let mut status = ZwOpenSection(&mut section_handle, SECTION_MAP_READ | SECTION_QUERY, &mut obj_attr);
    if !NT_SUCCESS(status) {
        log::error!("ZwOpenSection Failed With Status: {status}");
        return None
    }

    let mut large: LARGE_INTEGER = zeroed();
    let mut ntdll_addr = null_mut();
    let mut view_size = 0;
    status = ZwMapViewOfSection(
        section_handle, 
        0xFFFFFFFFFFFFFFFF as *mut core::ffi::c_void, 
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
        log::error!("ZwMapViewOfSection Failed With Status: {status}");
        ZwClose(section_handle);
        return None
    }

    let dos_header = ntdll_addr as *const IMAGE_DOS_HEADER;
    let nt_header = (ntdll_addr as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

    let ntdll_addr = ntdll_addr as usize;
    let export_directory = (ntdll_addr + (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let names = from_raw_parts((ntdll_addr + (*export_directory).AddressOfNames as usize) as *const u32, (*export_directory).NumberOfNames as _,);
    let functions = from_raw_parts((ntdll_addr + (*export_directory).AddressOfFunctions as usize) as *const u32, (*export_directory).NumberOfFunctions as _,);
    let ordinals = from_raw_parts((ntdll_addr + (*export_directory).AddressOfNameOrdinals as usize) as *const u16, (*export_directory).NumberOfNames as _);

    for i in 0..(*export_directory).NumberOfNames as isize {
        let name = CStr::from_ptr((ntdll_addr + names[i as usize] as usize) as *const i8).to_str().ok()?;
        let ordinal = ordinals[i as usize] as usize;
        let address = (ntdll_addr + functions[ordinal] as usize) as *const u8;
        if name == function_name && read(address) == 0x4C
                && read(address.add(1)) == 0x8B
                && read(address.add(2)) == 0xD1
                && read(address.add(3)) == 0xB8
                && read(address.add(6)) == 0x00
                && read(address.add(7)) == 0x00 
            {
                let high = read(address.add(5)) as u16;
                let low = read(address.add(4)) as u16;
                let ssn = (high << 8) | low;

                ZwUnmapViewOfSection(0xFFFFFFFFFFFFFFFF as *mut c_void, ntdll_addr as *mut c_void);
                ZwClose(section_handle);
                return Some(ssn);
            }
    }

    ZwUnmapViewOfSection(0xFFFFFFFFFFFFFFFF as *mut c_void, ntdll_addr as *mut c_void);
    ZwClose(section_handle);
    None
}