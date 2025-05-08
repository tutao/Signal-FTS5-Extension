//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::*;
use crate::signal_fts5_tokenize;
use core::ptr::null_mut;
use libc::{c_char, c_int, c_uchar, c_void};
use std::ffi::CString;

pub struct Sqlite3 {}
struct Sqlite3Stmt {}

pub const FTS5_API_VERSION: c_int = 2;

// fts5.h
#[repr(C)]
struct Fts5TokenizerApi {
    x_create: extern "C" fn(
        p_context: *mut c_void,
        az_arg: *const *const c_uchar,
        n_arg: c_int,
        fts5_tokenizer: *mut *mut Fts5Tokenizer,
    ) -> c_int,
    x_delete: extern "C" fn(fts5_tokenizer: *mut Fts5Tokenizer),
    x_tokenize: extern "C" fn(
        tokenizer: *mut Fts5Tokenizer,
        p_ctx: *mut c_void,
        flags: c_int,
        p_text: *const c_char,
        n_text: c_int,
        x_token: TokenFunction,
    ) -> c_int,
}

type Sqlite3Malloc64 = extern "C" fn(u64) -> *mut c_void;

type Sqlite3Prepare = extern "C" fn(
    db: *mut Sqlite3,
    query: *const c_char,
    query_len: c_int,
    stmt: *mut *mut Sqlite3Stmt,
    pz_tail: *mut *const c_char,
) -> c_int;

type Sqlite3Finalize = extern "C" fn(stmt: *mut Sqlite3Stmt) -> c_int;

type Sqlite3LibversionNumber = extern "C" fn() -> c_int;

type Sqlite3Step = extern "C" fn(stmt: *mut Sqlite3Stmt) -> c_int;

type Sqlite3BindPointer = extern "C" fn(
    stmt: *mut Sqlite3Stmt,
    index: c_int,
    ptr: *mut c_void,
    name: *const c_char,
    cb: Option<extern "C" fn(*mut c_void)>,
) -> c_int;

#[repr(C)]
struct FTS5API {
    i_version: c_int, // Currently always set to 2

    /* Create a new tokenizer */
    x_create_tokenizer: extern "C" fn(
        fts5_api: *const FTS5API,
        z_name: *const c_uchar,
        p_context: *mut c_void,
        fts5_tokenizer: *mut Fts5TokenizerApi,
        x_destroy: extern "C" fn(module: *mut c_void),
    ) -> c_int,
}

// sqlite3ext.h
#[repr(C)]
pub struct Sqlite3APIRoutines {
    _aggregate_context: extern "C" fn(),
    _aggregate_count: extern "C" fn(),
    _bind_blob: extern "C" fn(),
    _bind_double: extern "C" fn(),
    _bind_int: extern "C" fn(),
    _bind_int64: extern "C" fn(),
    _bind_null: extern "C" fn(),
    _bind_parameter_count: extern "C" fn(),
    _bind_parameter_index: extern "C" fn(),
    _bind_parameter_name: extern "C" fn(),
    _bind_text: extern "C" fn(),
    _bind_text16: extern "C" fn(),
    _bind_value: extern "C" fn(),
    _busy_handler: extern "C" fn(),
    _busy_timeout: extern "C" fn(),
    _changes: extern "C" fn(),
    _close: extern "C" fn(),
    _collation_needed: extern "C" fn(),
    _collation_needed16: extern "C" fn(),
    _column_blob: extern "C" fn(),
    _column_bytes: extern "C" fn(),
    _column_bytes16: extern "C" fn(),
    _column_count: extern "C" fn(),
    _column_database_name: extern "C" fn(),
    _column_database_name16: extern "C" fn(),
    _column_decltype: extern "C" fn(),
    _column_decltype16: extern "C" fn(),
    _column_double: extern "C" fn(),
    _column_int: extern "C" fn(),
    _column_int64: extern "C" fn(),
    _column_name: extern "C" fn(),
    _column_name16: extern "C" fn(),
    _column_origin_name: extern "C" fn(),
    _column_origin_name16: extern "C" fn(),
    _column_table_name: extern "C" fn(),
    _column_table_name16: extern "C" fn(),
    _column_text: extern "C" fn(),
    _column_text16: extern "C" fn(),
    _column_type: extern "C" fn(),
    _column_value: extern "C" fn(),
    _commit_hook: extern "C" fn(),
    _complete: extern "C" fn(),
    _complete16: extern "C" fn(),
    _create_collation: extern "C" fn(),
    _create_collation16: extern "C" fn(),
    _create_function: extern "C" fn(),
    _create_function16: extern "C" fn(),
    _create_module: extern "C" fn(),
    _data_count: extern "C" fn(),
    _db_handle: extern "C" fn(),
    _declare_vtab: extern "C" fn(),
    _enable_shared_cache: extern "C" fn(),
    _errcode: extern "C" fn(),
    _errmsg: extern "C" fn(),
    _errmsg16: extern "C" fn(),
    _exec: extern "C" fn(),
    _expired: extern "C" fn(),
    finalize: Sqlite3Finalize,
    _free: extern "C" fn(),
    _free_table: extern "C" fn(),
    _get_autocommit: extern "C" fn(),
    _get_auxdata: extern "C" fn(),
    _get_table: extern "C" fn(),
    _global_recover: extern "C" fn(),
    _interruptx: extern "C" fn(),
    _last_insert_rowid: extern "C" fn(),
    _libversion: extern "C" fn(),
    libversion_number: Sqlite3LibversionNumber,
    _malloc: extern "C" fn(),
    _mprintf: extern "C" fn(),
    _open: extern "C" fn(),
    _open16: extern "C" fn(),
    prepare: Sqlite3Prepare,
    _prepare16: extern "C" fn(),
    _profile: extern "C" fn(),
    _progress_handler: extern "C" fn(),
    _realloc: extern "C" fn(),
    _reset: extern "C" fn(),
    _result_blob: extern "C" fn(),
    _result_double: extern "C" fn(),
    _result_error: extern "C" fn(),
    _result_error16: extern "C" fn(),
    _result_int: extern "C" fn(),
    _result_int64: extern "C" fn(),
    _result_null: extern "C" fn(),
    _result_text: extern "C" fn(),
    _result_text16: extern "C" fn(),
    _result_text16be: extern "C" fn(),
    _result_text16le: extern "C" fn(),
    _result_value: extern "C" fn(),
    _rollback_hook: extern "C" fn(),
    _set_authorizer: extern "C" fn(),
    _set_auxdata: extern "C" fn(),
    _xsnprintf: extern "C" fn(),
    step: Sqlite3Step,
    _table_column_metadata: extern "C" fn(),
    _thread_cleanup: extern "C" fn(),
    _total_changes: extern "C" fn(),
    _trace: extern "C" fn(),
    _transfer_bindings: extern "C" fn(),
    _update_hook: extern "C" fn(),
    _user_data: extern "C" fn(),
    _value_blob: extern "C" fn(),
    _value_bytes: extern "C" fn(),
    _value_bytes16: extern "C" fn(),
    _value_double: extern "C" fn(),
    _value_int: extern "C" fn(),
    _value_int64: extern "C" fn(),
    _value_numeric_type: extern "C" fn(),
    _value_text: extern "C" fn(),
    _value_text16: extern "C" fn(),
    _value_text16be: extern "C" fn(),
    _value_text16le: extern "C" fn(),
    _value_type: extern "C" fn(),
    _vmprintf: extern "C" fn(),
    /* Added ??? */
    _overload_function: extern "C" fn(),
    /* Added by 3.3.13 */
    _prepare_v2: extern "C" fn(),
    _prepare16_v2: extern "C" fn(),
    _clear_bindings: extern "C" fn(),
    /* Added by 3.4.1 */
    _create_module_v2: extern "C" fn(),
    /* Added by 3.5.0 */
    _bind_zeroblob: extern "C" fn(),
    _blob_bytes: extern "C" fn(),
    _blob_close: extern "C" fn(),
    _blob_open: extern "C" fn(),
    _blob_read: extern "C" fn(),
    _blob_write: extern "C" fn(),
    _create_collation_v2: extern "C" fn(),
    _file_control: extern "C" fn(),
    _memory_highwater: extern "C" fn(),
    _memory_used: extern "C" fn(),
    _mutex_alloc: extern "C" fn(),
    _mutex_enter: extern "C" fn(),
    _mutex_free: extern "C" fn(),
    _mutex_leave: extern "C" fn(),
    _mutex_try: extern "C" fn(),
    _open_v2: extern "C" fn(),
    _release_memory: extern "C" fn(),
    _result_error_nomem: extern "C" fn(),
    _result_error_toobig: extern "C" fn(),
    _sleep: extern "C" fn(),
    _soft_heap_limit: extern "C" fn(),
    _vfs_find: extern "C" fn(),
    _vfs_register: extern "C" fn(),
    _vfs_unregister: extern "C" fn(),
    _xthreadsafe: extern "C" fn(),
    _result_zeroblob: extern "C" fn(),
    _result_error_code: extern "C" fn(),
    _test_control: extern "C" fn(),
    _randomness: extern "C" fn(),
    _context_db_handle: extern "C" fn(),
    _extended_result_codes: extern "C" fn(),
    _limit: extern "C" fn(),
    _next_stmt: extern "C" fn(),
    _sql: extern "C" fn(),
    _status: extern "C" fn(),
    _backup_finish: extern "C" fn(),
    _backup_init: extern "C" fn(),
    _backup_pagecount: extern "C" fn(),
    _backup_remaining: extern "C" fn(),
    _backup_step: extern "C" fn(),
    _compileoption_get: extern "C" fn(),
    _compileoption_used: extern "C" fn(),
    _create_function_v2: extern "C" fn(),
    _db_config: extern "C" fn(),
    _db_mutex: extern "C" fn(),
    _db_status: extern "C" fn(),
    _extended_errcode: extern "C" fn(),
    _log: extern "C" fn(),
    _soft_heap_limit64: extern "C" fn(),
    _sourceid: extern "C" fn(),
    _stmt_status: extern "C" fn(),
    _strnicmp: extern "C" fn(),
    _unlock_notify: extern "C" fn(),
    _wal_autocheckpoint: extern "C" fn(),
    _wal_checkpoint: extern "C" fn(),
    _wal_hook: extern "C" fn(),
    _blob_reopen: extern "C" fn(),
    _vtab_config: extern "C" fn(),
    _vtab_on_conflict: extern "C" fn(),
    /* Version 3.7.16 and later */
    _close_v2: extern "C" fn(),
    _db_filename: extern "C" fn(),
    _db_readonly: extern "C" fn(),
    _db_release_memory: extern "C" fn(),
    _errstr: extern "C" fn(),
    _stmt_busy: extern "C" fn(),
    _stmt_readonly: extern "C" fn(),
    _stricmp: extern "C" fn(),
    _uri_boolean: extern "C" fn(),
    _uri_int64: extern "C" fn(),
    _uri_parameter: extern "C" fn(),
    _xvsnprintf: extern "C" fn(),
    _wal_checkpoint_v2: extern "C" fn(),
    /* Version 3.8.7 and later */
    _auto_extension: extern "C" fn(),
    _bind_blob64: extern "C" fn(),
    _bind_text64: extern "C" fn(),
    _cancel_auto_extension: extern "C" fn(),
    _load_extension: extern "C" fn(),
    malloc64: Sqlite3Malloc64,
    _msize: extern "C" fn(),
    _realloc64: extern "C" fn(),
    _reset_auto_extension: extern "C" fn(),
    _result_blob64: extern "C" fn(),
    _result_text64: extern "C" fn(),
    _strglob: extern "C" fn(),
    /* Version 3.8.11 and later */
    _value_dup: extern "C" fn(),
    _value_free: extern "C" fn(),
    _result_zeroblob64: extern "C" fn(),
    _bind_zeroblob64: extern "C" fn(),
    /* Version 3.9.0 and later */
    _value_subtype: extern "C" fn(),
    _result_subtype: extern "C" fn(),
    /* Version 3.10.0 and later */
    _status64: extern "C" fn(),
    _strlike: extern "C" fn(),
    _db_cacheflush: extern "C" fn(),
    /* Version 3.12.0 and later */
    _system_errno: extern "C" fn(),
    /* Version 3.14.0 and later */
    _trace_v2: extern "C" fn(),
    _expanded_sql: extern "C" fn(),
    /* Version 3.18.0 and later */
    _set_last_insert_rowid: extern "C" fn(),
    /* Version 3.20.0 and later */
    _prepare_v3: extern "C" fn(),
    _prepare16_v3: extern "C" fn(),
    bind_pointer: Sqlite3BindPointer,
}

/// sqlite3 routines that are actually used by the tokenizer extension
#[repr(C)]
pub struct UsefulSqlite3ApiRoutines {
    malloc64: Sqlite3Malloc64,
    prepare: Sqlite3Prepare,
    bind_pointer: Sqlite3BindPointer,
    finalize: Sqlite3Finalize,
    step: Sqlite3Step,
    libversion_number: Sqlite3LibversionNumber,
}

/// Init sqlite3 without needing to access the whole sqlite3_api_routines vtable.
/// Blessed (literally) way to write extensions is to use SQLITE_EXTENSION_INIT family of macros
/// which uses vtable variable in scope instead of whatever is passed into the entry point.
/// We are doing this to be able to statically link against the extension but to still be able to
/// compile extension without needing to compile C first.
#[no_mangle]
pub extern "C" fn signal_fts5_tokenizer_init_static(
    db: *mut Sqlite3,
    pz_err_msg: *mut *mut c_char,
    api: &UsefulSqlite3ApiRoutines,
) -> c_int {
    let result = std::panic::catch_unwind(|| signal_fts_tokenizer_internal_init(db, &api))
        .unwrap_or_else(|e| {
            Err(Fts5InitError::new(
                SQLITE_INTERNAL,
                format!("Panicked! {e:?}"),
            ))
        });

    match result {
        Ok(_) => SQLITE_OK,
        Err(Fts5InitError { code, message }) => {
            if !pz_err_msg.is_null() {
                let message = CString::new(message).unwrap().into_bytes_with_nul();
                let into_message_ptr = (api.malloc64)(message.len() as u64);

                if !into_message_ptr.is_null() {
                    let allocated = unsafe {
                        std::slice::from_raw_parts_mut(into_message_ptr as *mut u8, message.len())
                    };
                    allocated.copy_from_slice(message.as_slice());
                    unsafe { *pz_err_msg = into_message_ptr as *mut c_char };
                }
            }
            code
        }
    }
}

#[no_mangle]
pub extern "C" fn signal_fts5_tokenizer_init(
    db: *mut Sqlite3,
    pz_err_msg: *mut *mut c_char,
    p_api: *const c_void,
) -> c_int {
    let api = unsafe { (p_api as *const Sqlite3APIRoutines).as_ref() }.expect("was not null...");
    let api = UsefulSqlite3ApiRoutines {
        malloc64: api.malloc64,
        prepare: api.prepare,
        bind_pointer: api.bind_pointer,
        finalize: api.finalize,
        step: api.step,
        libversion_number: api.libversion_number,
    };
    signal_fts5_tokenizer_init_static(db, pz_err_msg, &api)
}

struct Fts5InitError {
    code: c_int,
    message: String,
}

impl Fts5InitError {
    fn new<S: Into<String>>(code: c_int, message: S) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
fn signal_fts_tokenizer_internal_init(
    db: *mut Sqlite3,
    api: &UsefulSqlite3ApiRoutines,
) -> Result<(), Fts5InitError> {
    if (api.libversion_number)() < 302000 {
        return Err(Fts5InitError::new(
            SQLITE_MISUSE,
            format!("Invalid version number {}", (api.libversion_number)()),
        ));
    }

    let mut stmt = null_mut::<Sqlite3Stmt>();
    let rc = (api.prepare)(db, c"SELECT fts5(?1)".as_ptr(), -1, &mut stmt, null_mut());

    if rc != SQLITE_OK {
        return Err(Fts5InitError::new(rc, "api.prepare failed"));
    }

    let mut p_fts5_api = null_mut::<FTS5API>();
    let rc = (api.bind_pointer)(
        stmt,
        1,
        &mut p_fts5_api as *mut _ as *mut c_void,
        c"fts5_api_ptr".as_ptr(),
        None,
    );
    if rc != SQLITE_OK {
        (api.finalize)(stmt);
        return Err(Fts5InitError::new(rc, "api.bind_pointer failed"));
    }

    // Intentionally ignore return value, sqlite3 returns SQLITE_ROW
    (api.step)(stmt);

    let rc = (api.finalize)(stmt);
    if rc != SQLITE_OK {
        return Err(Fts5InitError::new(rc, "finalize failed"));
    }

    let fts5_api = unsafe { p_fts5_api.as_ref() }
        .ok_or_else(|| Fts5InitError::new(SQLITE_INTERNAL, "FTS5 API was null"))?;

    // Newer versions add locale-aware v2 versions of the tokenizer methods but we don't use them
    // yet.
    if fts5_api.i_version < FTS5_API_VERSION {
        return Err(Fts5InitError::new(
            SQLITE_MISUSE,
            format!(
                "FTS5 API version mismatch {} < {FTS5_API_VERSION}",
                fts5_api.i_version
            ),
        ));
    }

    // Add custom tokenizer
    let mut tokenizer = Fts5TokenizerApi {
        x_create: fts5_create_signal_tokenizer,
        x_delete: fts5_delete_signal_tokenizer,
        x_tokenize: signal_fts5_tokenize,
    };

    (fts5_api.x_create_tokenizer)(
        fts5_api,
        b"signal_tokenizer\0".as_ptr(),
        null_mut(),
        &mut tokenizer,
        fts5_destroy_icu_module,
    );

    Ok(())
}

#[no_mangle]
pub extern "C" fn fts5_create_signal_tokenizer(
    _p_context: *mut c_void,
    _az_arg: *const *const c_uchar,
    _n_arg: c_int,
    fts5_tokenizer: *mut *mut Fts5Tokenizer,
) -> c_int {
    let tokenizer = Box::new(Fts5Tokenizer {});
    unsafe {
        *fts5_tokenizer = Box::into_raw(tokenizer);
    }
    return SQLITE_OK;
}

#[no_mangle]
pub extern "C" fn fts5_delete_signal_tokenizer(fts5_tokenizer: *mut Fts5Tokenizer) {
    let tokenizer = unsafe { Box::from_raw(fts5_tokenizer) };
    drop(tokenizer);
}

#[no_mangle]
pub extern "C" fn fts5_destroy_icu_module(_module: *mut c_void) {
    // no-op
}
