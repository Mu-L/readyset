// Copyright 2021 TiKV Project Authors. Licensed under Apache-2.0.

// The implementation of this crate when jemalloc is turned on

use std::collections::HashMap;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::{slice, thread};

use libc::{self, c_char, c_void};
use tikv_jemalloc_ctl::{epoch, stats, Error};
use tikv_jemalloc_sys::malloc_stats_print;

use super::error::{ProfError, ProfResult};
use crate::{AllocStats, AllocThreadStats};

pub type Allocator = tikv_jemallocator::Jemalloc;
pub const fn allocator() -> Allocator {
    tikv_jemallocator::Jemalloc
}

lazy_static! {
    static ref THREAD_MEMORY_MAP: Mutex<HashMap<ThreadId, MemoryStatsAccessor>> =
        Mutex::new(HashMap::new());
}

/// The struct for tracing the statistic of another thread.
/// The target pointer should be bound to some TLS of another thread, this
/// structure is just "peeking" it -- with out modifying.
// It should be covariant so we wrap it with `NonNull`.
#[repr(transparent)]
struct PeekableRemoteStat<T>(Option<NonNull<T>>);

// SAFETY: all constructors of `PeekableRemoteStat` returns pointer points to a
// thread local variable. Once this be sent, a reasonable life time of this
// variable should be as long as the thread holding the underlying thread local
// variable. But it is impossible to express such lifetime in current Rust.
// Then it is the user's responsibility to trace that lifetime.
unsafe impl<T: Send> Send for PeekableRemoteStat<T> {}

impl<T: Copy> PeekableRemoteStat<T> {
    fn from_raw(ptr: *mut T) -> Self {
        Self(NonNull::new(ptr))
    }
}

impl PeekableRemoteStat<u64> {
    /// Try access the underlying data. When the pointer is `nullptr`, returns
    /// `None`.
    ///
    /// # Safety
    ///
    /// The pointer should not be dangling. (i.e. the thread to be traced should
    /// be accessible.)
    unsafe fn peek(&self) -> Option<u64> {
        self.0
            .map(|nlp| unsafe { AtomicU64::from_ptr(nlp.as_ptr()).load(Ordering::SeqCst) })
    }

    fn allocated() -> Self {
        // SAFETY: it is transparent.
        // NOTE: perhaps we'd better add something like `as_raw()` for `ThreadLocal`...
        Self::from_raw(
            tikv_jemalloc_ctl::thread::allocatedp::read()
                .map(|x| unsafe { std::mem::transmute(x) })
                .unwrap_or(std::ptr::null_mut()),
        )
    }

    fn deallocated() -> Self {
        // SAFETY: it is transparent.
        Self::from_raw(
            tikv_jemalloc_ctl::thread::deallocatedp::read()
                .map(|x| unsafe { std::mem::transmute(x) })
                .unwrap_or(std::ptr::null_mut()),
        )
    }
}

struct MemoryStatsAccessor {
    allocated: PeekableRemoteStat<u64>,
    deallocated: PeekableRemoteStat<u64>,
    thread_name: String,
}

impl MemoryStatsAccessor {
    fn get_allocated(&self) -> u64 {
        // SAFETY: `add_thread_memory_accessor` is unsafe, and that is the only way for
        // outer crates to create this.
        unsafe { self.allocated.peek().unwrap_or_default() }
    }

    fn get_deallocated(&self) -> u64 {
        // SAFETY: `add_thread_memory_accessor` is unsafe, and that is the only way for
        // outer crates to create this.
        unsafe { self.deallocated.peek().unwrap_or_default() }
    }
}

/// Register the current thread to the collector that collects the jemalloc
/// allocation / deallocation info.
///
/// Generally you should call this via `spawn_wrapper`s instead of invoke this
/// directly. The former is a safe function.
///
/// # Safety
///
/// Make sure the `remove_thread_memory_accessor` is called before the thread
/// exits.
pub unsafe fn add_thread_memory_accessor() {
    let mut thread_memory_map = THREAD_MEMORY_MAP.lock().unwrap();
    thread_memory_map
        .entry(thread::current().id())
        .or_insert_with(|| {
            let allocated = PeekableRemoteStat::allocated();
            let deallocated = PeekableRemoteStat::deallocated();

            MemoryStatsAccessor {
                thread_name: thread::current().name().unwrap_or("<unknown>").to_string(),
                allocated,
                deallocated,
            }
        });
}

pub fn remove_thread_memory_accessor() {
    let mut thread_memory_map = THREAD_MEMORY_MAP.lock().unwrap();
    thread_memory_map.remove(&thread::current().id());
}

use std::thread::ThreadId;

pub use self::profiling::{activate_prof, deactivate_prof, dump_prof, dump_prof_to_string};

/// Returns a very verbose output of jemalloc stats as well as per-thread stats
pub fn dump_stats() -> Result<String, Error> {
    // Stats are cached. Need to advance epoch to refresh.
    epoch::advance()?;
    let mut buf = Vec::with_capacity(1024);

    unsafe {
        malloc_stats_print(
            Some(write_cb),
            &mut buf as *mut Vec<u8> as *mut c_void,
            ptr::null(),
        );
    }
    let mut memory_stats = format!(
        "Memory stats summary: {}\n",
        String::from_utf8_lossy(&buf).into_owned()
    );
    memory_stats.push_str("Memory stats by thread:\n");

    let thread_memory_map = THREAD_MEMORY_MAP.lock().unwrap();
    for (_, accessor) in thread_memory_map.iter() {
        let alloc = accessor.get_allocated();
        let dealloc = accessor.get_deallocated();
        memory_stats.push_str(
            format!(
                "Thread [{}]: alloc_bytes={alloc},dealloc_bytes={dealloc}\n",
                accessor.thread_name
            )
            .as_str(),
        );
    }
    Ok(memory_stats)
}

/// Returns a summary of the memory usage for the entire process
pub fn fetch_stats() -> Result<AllocStats, Error> {
    // Stats are cached. Need to advance epoch to refresh.
    epoch::advance()?;
    fetch_stats_inner()
}

fn fetch_stats_inner() -> Result<AllocStats, Error> {
    let resident = stats::resident::read()?;
    let active = stats::active::read()?;
    let metadata = stats::metadata::read()?;
    let allocated = stats::allocated::read()?;

    Ok(AllocStats {
        allocated,
        active,
        metadata,
        resident,
        mapped: stats::mapped::read()?,
        retained: stats::retained::read()?,
        dirty: resident.saturating_sub(active + metadata),
        fragmentation: active.saturating_sub(allocated),
    })
}

pub fn fetch_thread_memory_stats() -> Result<Vec<AllocThreadStats>, Error> {
    // Stats are cached. Need to advance epoch to refresh.
    epoch::advance()?;
    Ok(fetch_thread_memory_stats_inner())
}

fn fetch_thread_memory_stats_inner() -> Vec<AllocThreadStats> {
    let thread_memory_map = THREAD_MEMORY_MAP.lock().unwrap();
    thread_memory_map
        .values()
        .map(|accessor| AllocThreadStats {
            thread_name: accessor.thread_name.clone(),
            allocated: accessor.get_allocated(),
            deallocated: accessor.get_deallocated(),
        })
        .collect()
}

// Stats are cached. Need to advance epoch to refresh; but want same epoch for global and
// per-thread, so bundle them in one call.
pub fn fetch_all_memory_stats() -> Result<(AllocStats, Vec<AllocThreadStats>), Error> {
    epoch::advance()?;
    Ok((fetch_stats_inner()?, fetch_thread_memory_stats_inner()))
}

/// Prints both a summary of the entire process memory usage as well as a per-thread breakdown for
/// any threads that have been registered with the global memory map
pub fn print_memory_and_per_thread_stats() -> Result<String, Error> {
    // Stats are cached. Need to advance epoch to refresh.
    epoch::advance()?;
    let mut memory_stats = format!("Memory stats summary: {:?}\n", fetch_stats_inner()?);
    memory_stats.push_str("Memory stats by thread:\n");
    for AllocThreadStats {
        thread_name,
        allocated,
        deallocated,
    } in fetch_thread_memory_stats_inner()
    {
        memory_stats.push_str(
            format!(
                "Thread [{thread_name}]: alloc_bytes={allocated},dealloc_bytes={deallocated}\n",
            )
            .as_str(),
        );
    }

    Ok(memory_stats)
}

#[allow(clippy::cast_ptr_alignment)]
extern "C" fn write_cb(printer: *mut c_void, msg: *const c_char) {
    unsafe {
        // This cast from *c_void to *Vec<u8> looks like a bad
        // cast to clippy due to pointer alignment, but we know
        // what type the pointer is.
        let buf = &mut *(printer as *mut Vec<u8>);
        let len = libc::strlen(msg);
        let bytes = slice::from_raw_parts(msg as *const u8, len);
        buf.extend_from_slice(bytes);
    }
}

#[cfg(test)]
mod tests {
    use crate::imp::THREAD_MEMORY_MAP;
    use crate::{add_thread_memory_accessor, remove_thread_memory_accessor};

    fn assert_delta(name: impl std::fmt::Display, delta: f64, a: u64, b: u64) {
        let (base, diff) = if a > b { (a, a - b) } else { (b, b - a) };
        let error = diff as f64 / base as f64;
        assert!(
            error < delta,
            "{name}: the error is too huge: a={a}, b={b}, base={base}, diff={diff}, error={error}"
        );
    }
    #[test]
    fn dump_stats() {
        assert_ne!(super::dump_stats().unwrap().len(), 0);
    }

    #[test]
    fn test_allocation_stat() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut threads = vec![];
        for i in 1..6 {
            let tx = tx.clone();
            // It is in test... let skip calling hooks.
            #[allow(clippy::disallowed_methods)]
            let hnd = std::thread::Builder::new()
                .name(format!("test_allocation_stat_{i}"))
                .spawn(move || {
                    if i == 5 {
                        return;
                    }
                    // SAFETY: we call `remove_thread_memory_accessor` below.
                    unsafe {
                        add_thread_memory_accessor();
                    }
                    let (tx2, rx2) = std::sync::mpsc::channel::<()>();
                    let v = vec![42u8; 1024 * 1024 * i];
                    drop(v);
                    let _v2 = vec![42u8; 512 * 1024 * i];
                    tx.send((i, std::thread::current().id(), tx2)).unwrap();
                    drop(tx);
                    rx2.recv().unwrap();
                    remove_thread_memory_accessor();
                })
                .unwrap();
            threads.push(hnd);
        }
        drop(tx);

        let chs = rx.into_iter().collect::<Vec<_>>();
        let l = THREAD_MEMORY_MAP.lock().unwrap();
        for (i, tid, tx) in chs {
            let a = l.get(&tid).unwrap();
            unsafe {
                let alloc = a.allocated.peek().unwrap();
                let dealloc = a.deallocated.peek().unwrap();
                assert_delta(i, 0.05, alloc, (1024 + 512) * 1024 * i as u64);
                assert_delta(i, 0.05, dealloc, (1024) * 1024 * i as u64);
            }
            tx.send(()).unwrap();
        }
        drop(l);
        for th in threads.into_iter() {
            th.join().unwrap();
        }
    }
}

#[cfg(feature = "mem-profiling")]
mod profiling {
    use std::{ffi::CString, os::unix::ffi::OsStrExt, path::Path};

    use libc::c_char;

    use super::{ProfError, ProfResult};

    // C string should end with a '\0'.
    const PROF_ACTIVE: &[u8] = b"prof.active\0";
    const PROF_DUMP: &[u8] = b"prof.dump\0";

    pub fn activate_prof() -> ProfResult<()> {
        unsafe {
            if let Err(e) = tikv_jemalloc_ctl::raw::update(PROF_ACTIVE, true) {
                return Err(ProfError::JemallocError(format!(
                    "failed to activate profiling: {e}"
                )));
            }
        }
        Ok(())
    }

    pub fn deactivate_prof() -> ProfResult<()> {
        unsafe {
            if let Err(e) = tikv_jemalloc_ctl::raw::update(PROF_ACTIVE, false) {
                return Err(ProfError::JemallocError(format!(
                    "failed to deactivate profiling: {e}"
                )));
            }
        }
        Ok(())
    }

    /// Dump the profile to the `path`.
    pub fn dump_prof(path: impl AsRef<Path>) -> ProfResult<()> {
        let mut bytes = CString::new(path.as_ref().as_os_str().as_bytes())?.into_bytes_with_nul();
        let ptr = bytes.as_mut_ptr() as *mut c_char;
        unsafe {
            if let Err(e) = tikv_jemalloc_ctl::raw::write(PROF_DUMP, ptr) {
                return Err(ProfError::JemallocError(format!(
                    "failed to dump the profile to {:?}: {}",
                    path.as_ref(),
                    e
                )));
            }
        }
        Ok(())
    }

    pub async fn dump_prof_to_string() -> ProfResult<String> {
        let tempdir = tempfile::Builder::new().prefix("jeprof").tempdir()?;
        let path = tempdir.path().join("jeprof.out");
        dump_prof(&path)?;
        Ok(tokio::fs::read_to_string(path).await?)
    }

    #[cfg(test)]
    mod tests {
        use std::fs;

        const OPT_PROF: &[u8] = b"opt.prof\0";

        fn is_profiling_on() -> bool {
            match unsafe { tikv_jemalloc_ctl::raw::read(OPT_PROF) } {
                Err(e) => {
                    // Shouldn't be possible since mem-profiling is set
                    panic!("is_profiling_on: {e:?}");
                }
                Ok(prof) => prof,
            }
        }

        // Only trigger this test with jemallocs `opt.prof` set to
        // true ala `MALLOC_CONF="prof:true"`. It can be run by
        // passing `-- --ignored` to `cargo test -p tikv_alloc`.
        //
        // TODO: could probably unignore this by running a second
        // copy of the executable with MALLOC_CONF set.
        //
        // TODO: need a test for the dump_prof(None) case, but
        // the cleanup afterward is not simple.
        #[test]
        #[ignore = "#ifdef MALLOC_CONF"]
        fn test_profiling_memory_ifdef_malloc_conf() {
            // Make sure somebody has turned on profiling
            assert!(is_profiling_on(), "set MALLOC_CONF=prof:true");

            let dir = tempfile::Builder::new()
                .prefix("test_profiling_memory")
                .tempdir()
                .unwrap();

            let path = dir.path().join("test1.dump");
            super::dump_prof(&path).unwrap();

            let path = dir.path().join("test2.dump");
            super::dump_prof(&path).unwrap();

            let files = fs::read_dir(dir.path()).unwrap().count();
            assert_eq!(files, 2);

            // Find the created files and check properties that
            // indicate they contain something interesting
            let mut prof_count = 0;
            for file_entry in fs::read_dir(dir.path()).unwrap() {
                let file_entry = file_entry.unwrap();
                let path = file_entry.path().to_str().unwrap().to_owned();
                if path.contains("test1.dump") || path.contains("test2.dump") {
                    let metadata = file_entry.metadata().unwrap();
                    let file_len = metadata.len();
                    assert!(file_len > 10); // arbitrary number
                    prof_count += 1
                }
            }
            assert_eq!(prof_count, 2);
        }
    }
}

#[cfg(not(feature = "mem-profiling"))]
mod profiling {
    use super::{ProfError, ProfResult};

    pub fn activate_prof() -> ProfResult<()> {
        Err(ProfError::MemProfilingNotEnabled)
    }
    pub fn deactivate_prof() -> ProfResult<()> {
        Err(ProfError::MemProfilingNotEnabled)
    }
    pub fn dump_prof(path: impl AsRef<Path>) -> ProfResult<()> {
        Err(ProfError::MemProfilingNotEnabled)
    }
    pub async fn dump_prof_to_string() -> ProfResult<String> {
        Err(ProfError::MemProfilingNotEnabled)
    }
}
