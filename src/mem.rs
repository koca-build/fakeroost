//! Reading and writing a tracee's memory.
//!
//! We use `process_vm_readv`/`process_vm_writev` (one syscall per transfer, no
//! per-word ptrace round-trips). These need the same permissions as ptrace, which
//! we already have over our own children.

use crate::error::{Error, Result};
use nix::sys::uio::{RemoteIoVec, process_vm_readv, process_vm_writev};
use nix::unistd::Pid;
use std::io::{IoSlice, IoSliceMut};

/// Read `buf.len()` bytes from the tracee at `addr`.
pub fn read(pid: Pid, addr: u64, buf: &mut [u8]) -> Result<()> {
    let remote = RemoteIoVec {
        base: addr as usize,
        len: buf.len(),
    };
    let n = process_vm_readv(pid, &mut [IoSliceMut::new(buf)], &[remote])?;
    if n != buf.len() {
        return Err(Error::Other(format!(
            "short read from tracee: {n}/{} bytes",
            buf.len()
        )));
    }
    Ok(())
}

/// Write `buf` to the tracee at `addr`.
pub fn write(pid: Pid, addr: u64, buf: &[u8]) -> Result<()> {
    let remote = RemoteIoVec {
        base: addr as usize,
        len: buf.len(),
    };
    let n = process_vm_writev(pid, &[IoSlice::new(buf)], &[remote])?;
    if n != buf.len() {
        return Err(Error::Other(format!(
            "short write to tracee: {n}/{} bytes",
            buf.len()
        )));
    }
    Ok(())
}

/// Read a POD value of type `T` from the tracee. `T` must be a `#[repr(C)]` type
/// whose layout matches what the kernel wrote (e.g. `libc::stat`, `libc::statx`).
pub fn read_struct<T: Copy>(pid: Pid, addr: u64) -> Result<T> {
    let mut val = std::mem::MaybeUninit::<T>::zeroed();
    // SAFETY: we fill exactly size_of::<T>() bytes before assume_init.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(val.as_mut_ptr().cast::<u8>(), std::mem::size_of::<T>())
    };
    read(pid, addr, bytes)?;
    Ok(unsafe { val.assume_init() })
}

/// Read a NUL-terminated C string from the tracee at `addr` (without the NUL).
///
/// Reads in page-bounded chunks so we never run off the end of a mapping while
/// scanning for the terminator.
pub fn read_cstring(pid: Pid, mut addr: u64) -> Result<Vec<u8>> {
    const PAGE: u64 = 4096;
    const MAX: usize = 4096; // PATH_MAX
    let mut out = Vec::new();
    loop {
        let to_page_end = (PAGE - (addr % PAGE)) as usize;
        let chunk = to_page_end.min(256);
        let mut buf = vec![0u8; chunk];
        read(pid, addr, &mut buf)?;
        if let Some(pos) = buf.iter().position(|&b| b == 0) {
            out.extend_from_slice(&buf[..pos]);
            return Ok(out);
        }
        out.extend_from_slice(&buf);
        if out.len() > MAX {
            return Err(Error::Other("path from tracee exceeds PATH_MAX".into()));
        }
        addr += chunk as u64;
    }
}

/// Write a POD value of type `T` to the tracee.
pub fn write_struct<T: Copy>(pid: Pid, addr: u64, val: &T) -> Result<()> {
    // SAFETY: reading the bytes of a Copy value is sound.
    let bytes = unsafe {
        std::slice::from_raw_parts((val as *const T).cast::<u8>(), std::mem::size_of::<T>())
    };
    write(pid, addr, bytes)
}
