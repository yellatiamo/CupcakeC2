//! Worker I/O ABI shared between `reflective_loader` and the L2 worker modules
//! (inject / ad). The loader spawns the sacrificial host *suspended* and wires
//! dedicated anonymous pipes for the job frame and the result frame. The worker
//! thread receives a `WorkerIo` struct (written into a param page in the child)
//! as its thread parameter, so host stdio (banner output, stdin reads) can never
//! corrupt the framed protocol.
//!
//! ABI (stable, both crates must keep this layout):
//! ```text
//! offset 0: u64 job_read      — pipe read end for the job frame (child-relative)
//! offset 8: u64 result_write  — pipe write end for the result frame (child-relative)
//! ```
//! Total size: 16 bytes. Handles are duplicated into the child by the loader and
//! are valid only in the child process.

/// Worker I/O descriptor (thread param target in child memory).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WorkerIo {
    /// Child-relative handle: read end of the job pipe.
    pub job_read: u64,
    /// Child-relative handle: write end of the result pipe.
    pub result_write: u64,
}

impl WorkerIo {
    pub const SIZE: usize = 16;

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&self.job_read.to_le_bytes());
        b[8..16].copy_from_slice(&self.result_write.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Self {
        let job = if b.len() >= 8 {
            u64::from_le_bytes(b[0..8].try_into().unwrap())
        } else {
            0
        };
        let res = if b.len() >= 16 {
            u64::from_le_bytes(b[8..16].try_into().unwrap())
        } else {
            0
        };
        WorkerIo {
            job_read: job,
            result_write: res,
        }
    }
}

/// Read exactly `buf.len()` bytes from a raw (child-relative) handle.
/// The handle is not closed (ownership stays with the child/loader).
pub fn read_exact_handle(handle: u64, buf: &mut [u8]) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::io::Read;
        use std::os::windows::io::{FromRawHandle, RawHandle};
        unsafe {
            let f = std::fs::File::from_raw_handle(handle as RawHandle);
            let mut f = std::mem::ManuallyDrop::new(f);
            f.read_exact(buf).map_err(|e| e.to_string())
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (handle, buf);
        Err("worker_io: windows only".into())
    }
}

/// Write all bytes to a raw (child-relative) handle. The handle is not closed.
pub fn write_all_handle(handle: u64, data: &[u8]) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::io::Write;
        use std::os::windows::io::{FromRawHandle, RawHandle};
        unsafe {
            let f = std::fs::File::from_raw_handle(handle as RawHandle);
            let mut f = std::mem::ManuallyDrop::new(f);
            f.write_all(data).map_err(|e| e.to_string())?;
            f.flush().map_err(|e| e.to_string())
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (handle, data);
        Err("worker_io: windows only".into())
    }
}
