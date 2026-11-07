use crate::server_instances::application::{
    incidents::JournalCheckpoint,
    journal_replay::{JournalReadFuture, JournalReader},
};

pub struct SystemJournalReader;

impl JournalReader for SystemJournalReader {
    fn read<'a>(
        &'a self,
        unit: &'a str,
        after: Option<&'a JournalCheckpoint>,
        limit: usize,
    ) -> JournalReadFuture<'a> {
        let unit = unit.to_owned();
        let after = after.cloned();
        Box::pin(async move {
            #[cfg(target_os = "linux")]
            {
                tokio::task::spawn_blocking(move || linux::read(&unit, after.as_ref(), limit))
                    .await
                    .map_err(|error| error.to_string())?
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (unit, after, limit);
                Err("journald is only available on Linux".into())
            }
        })
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        ffi::{CStr, CString},
        ptr,
    };

    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    use super::*;
    use crate::server_instances::application::journal_replay::{JournalEntry, JournalPage};

    type Open = unsafe extern "C" fn(*mut *mut libc::c_void, libc::c_int) -> libc::c_int;
    type Close = unsafe extern "C" fn(*mut libc::c_void);
    type Match =
        unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, libc::size_t) -> libc::c_int;
    type Seek = unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int;
    type SeekCursor = unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char) -> libc::c_int;
    type Next = unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int;
    type TestCursor = unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char) -> libc::c_int;
    type GetCursor = unsafe extern "C" fn(*mut libc::c_void, *mut *mut libc::c_char) -> libc::c_int;
    type GetData = unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_char,
        *mut *const libc::c_void,
        *mut libc::size_t,
    ) -> libc::c_int;
    type GetTime = unsafe extern "C" fn(*mut libc::c_void, *mut u64) -> libc::c_int;
    type Persistent = unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int;

    struct Api {
        handle: *mut libc::c_void,
        open: Open,
        close: Close,
        add_match: Match,
        seek_head: Seek,
        seek_cursor: SeekCursor,
        next: Next,
        test_cursor: TestCursor,
        get_cursor: GetCursor,
        get_data: GetData,
        get_time: GetTime,
        persistent: Persistent,
    }

    impl Api {
        fn load() -> Result<Self, String> {
            let library = CString::new("libsystemd.so.0").unwrap();
            // SAFETY: dlopen returns a handle owned by Api; each symbol is
            // resolved from that handle and kept alive until the journal closes.
            let handle =
                unsafe { libc::dlopen(library.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if handle.is_null() {
                return Err("libsystemd.so.0 is unavailable".into());
            }
            let result = (|| {
                // SAFETY: these are the published libsystemd C signatures.
                unsafe {
                    Ok(Self {
                        handle,
                        open: symbol(handle, b"sd_journal_open\0")?,
                        close: symbol(handle, b"sd_journal_close\0")?,
                        add_match: symbol(handle, b"sd_journal_add_match\0")?,
                        seek_head: symbol(handle, b"sd_journal_seek_head\0")?,
                        seek_cursor: symbol(handle, b"sd_journal_seek_cursor\0")?,
                        next: symbol(handle, b"sd_journal_next\0")?,
                        test_cursor: symbol(handle, b"sd_journal_test_cursor\0")?,
                        get_cursor: symbol(handle, b"sd_journal_get_cursor\0")?,
                        get_data: symbol(handle, b"sd_journal_get_data\0")?,
                        get_time: symbol(handle, b"sd_journal_get_realtime_usec\0")?,
                        persistent: symbol(handle, b"sd_journal_has_persistent_files\0")?,
                    })
                }
            })();
            if result.is_err() {
                unsafe {
                    libc::dlclose(handle);
                }
            }
            result
        }
    }

    // SAFETY: caller supplies the exact function pointer type of the named
    // libsystemd symbol, and Api owns the library for the pointer's lifetime.
    unsafe fn symbol<T: Copy>(handle: *mut libc::c_void, name: &[u8]) -> Result<T, String> {
        let pointer = unsafe { libc::dlsym(handle, name.as_ptr().cast()) };
        if pointer.is_null() {
            return Err(format!(
                "missing libsystemd symbol {}",
                String::from_utf8_lossy(name)
            ));
        }
        if std::mem::size_of::<T>() != std::mem::size_of::<*mut libc::c_void>() {
            return Err("invalid function pointer size".into());
        }
        Ok(unsafe { std::mem::transmute_copy(&pointer) })
    }

    struct Journal {
        api: Api,
        pointer: *mut libc::c_void,
    }
    impl Drop for Journal {
        fn drop(&mut self) {
            unsafe {
                (self.api.close)(self.pointer);
                libc::dlclose(self.api.handle);
            }
        }
    }

    fn check(code: libc::c_int, name: &str) -> Result<(), String> {
        if code < 0 {
            Err(format!(
                "{name}: {}",
                std::io::Error::from_raw_os_error(-code)
            ))
        } else {
            Ok(())
        }
    }

    pub fn read(
        unit: &str,
        after: Option<&JournalCheckpoint>,
        limit: usize,
    ) -> Result<JournalPage, String> {
        let api = Api::load()?;
        let mut pointer = ptr::null_mut();
        // 1 = SD_JOURNAL_LOCAL_ONLY, 4 = SD_JOURNAL_SYSTEM.
        let code = unsafe { (api.open)(&mut pointer, 1 | 4) };
        if code < 0 {
            unsafe {
                libc::dlclose(api.handle);
            }
            check(code, "sd_journal_open")?;
        }
        let journal = Journal { api, pointer };
        let persistent = unsafe { (journal.api.persistent)(pointer) };
        check(persistent, "sd_journal_has_persistent_files")?;
        if persistent == 0 {
            return Ok(JournalPage {
                entries: vec![],
                cursor_found: false,
                persistent: false,
            });
        }

        let match_unit = format!("UNIT={unit}");
        check(
            unsafe {
                (journal.api.add_match)(pointer, match_unit.as_ptr().cast(), match_unit.len())
            },
            "sd_journal_add_match",
        )?;
        // UNIT and MESSAGE_ID may be supplied by applications; _PID is
        // trusted metadata assigned by journald to the system manager.
        let manager = b"_PID=1";
        check(
            unsafe { (journal.api.add_match)(pointer, manager.as_ptr().cast(), manager.len()) },
            "sd_journal_add_match manager",
        )?;
        let mut cursor_found = after.is_none();
        if let Some(checkpoint) = after {
            let cursor =
                CString::new(checkpoint.cursor.as_str()).map_err(|error| error.to_string())?;
            check(
                unsafe { (journal.api.seek_cursor)(pointer, cursor.as_ptr()) },
                "sd_journal_seek_cursor",
            )?;
            let next = unsafe { (journal.api.next)(pointer) };
            check(next, "sd_journal_next")?;
            if next > 0 {
                let found = unsafe { (journal.api.test_cursor)(pointer, cursor.as_ptr()) };
                check(found, "sd_journal_test_cursor")?;
                cursor_found = found > 0;
            }
            if !cursor_found {
                check(
                    unsafe { (journal.api.seek_head)(pointer) },
                    "sd_journal_seek_head",
                )?;
            }
        } else {
            check(
                unsafe { (journal.api.seek_head)(pointer) },
                "sd_journal_seek_head",
            )?;
        }

        let mut entries = Vec::with_capacity(limit.min(256));
        while entries.len() < limit {
            let next = unsafe { (journal.api.next)(pointer) };
            check(next, "sd_journal_next")?;
            if next == 0 {
                break;
            }
            let boot_id = field(&journal, "_BOOT_ID")?.ok_or("journal entry lacks _BOOT_ID")?;
            let boot_id = Uuid::parse_str(&boot_id).map_err(|error| error.to_string())?;
            let mut cursor = ptr::null_mut();
            check(
                unsafe { (journal.api.get_cursor)(pointer, &mut cursor) },
                "sd_journal_get_cursor",
            )?;
            let cursor_string = unsafe { CStr::from_ptr(cursor).to_string_lossy().into_owned() };
            unsafe {
                libc::free(cursor.cast());
            }
            let mut micros = 0_u64;
            check(
                unsafe { (journal.api.get_time)(pointer, &mut micros) },
                "sd_journal_get_realtime_usec",
            )?;
            let occurred_at = DateTime::<Utc>::from_timestamp_micros(
                i64::try_from(micros).map_err(|error| error.to_string())?,
            )
            .ok_or("journal timestamp is out of range")?;
            entries.push(JournalEntry {
                boot_id,
                cursor: cursor_string,
                occurred_at,
                message_id: field(&journal, "MESSAGE_ID")?,
                result: field(&journal, "RESULT")?,
                invocation_id: field(&journal, "INVOCATION_ID")?,
            });
        }
        Ok(JournalPage {
            entries,
            cursor_found,
            persistent: true,
        })
    }

    fn field(journal: &Journal, key: &str) -> Result<Option<String>, String> {
        let key_c = CString::new(key).unwrap();
        let mut data = ptr::null();
        let mut len = 0;
        let code =
            unsafe { (journal.api.get_data)(journal.pointer, key_c.as_ptr(), &mut data, &mut len) };
        if code == -libc::ENOENT {
            return Ok(None);
        }
        check(code, "sd_journal_get_data")?;
        let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len) };
        let value = bytes
            .strip_prefix(format!("{key}=").as_bytes())
            .ok_or("journal field name mismatch")?;
        Ok(Some(String::from_utf8_lossy(value).into_owned()))
    }
}
