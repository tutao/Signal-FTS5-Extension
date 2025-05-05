//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

extern crate alloc;

mod common;
#[cfg(feature = "extension")]
mod extension;

pub use crate::common::*;
use libc::{c_char, c_int, c_uchar, c_void};
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

#[no_mangle]
pub extern "C" fn signal_fts5_tokenize(
    _tokenizer: *mut Fts5Tokenizer,
    p_ctx: *mut c_void,
    _flags: c_int,
    p_text: *const c_char,
    n_text: c_int,
    x_token: TokenFunction,
) -> c_int {
    std::panic::catch_unwind(|| {
        match signal_fts5_tokenize_internal(p_ctx, p_text, n_text, x_token) {
            Ok(()) => SQLITE_OK,
            Err(code) => code,
        }
    })
    .unwrap_or(SQLITE_INTERNAL)
}

fn signal_fts5_tokenize_internal(
    p_ctx: *mut c_void,
    p_text: *const c_char,
    n_text: c_int,
    x_token: TokenFunction,
) -> Result<(), c_int> {
    let slice = unsafe { core::slice::from_raw_parts(p_text as *const c_uchar, n_text as usize) };

    // Map errors to SQLITE_OK because failing here means that the database
    // wouldn't accessible.
    let input = core::str::from_utf8(slice).map_err(|_| SQLITE_OK)?;

    let mut normalized = String::with_capacity(1024);

    // unicode_word_indices does not split on everything that we would like to turn into a token
    // e.g. '.'. We are adding our own pass after segmentation.
    for (off, segment) in input.unicode_word_indices() {
        let mut offset = off;
        for word in segment.split(should_split_on) {
            normalize_into(word, &mut normalized);
            let rc = x_token(
                p_ctx,
                0,
                normalized.as_bytes().as_ptr() as *const c_char,
                normalized.len() as c_int,
                offset as c_int,
                (offset + word.len()) as c_int,
            );
            if rc != SQLITE_OK {
                return Err(rc);
            }
            offset += word.len() + 1; // assumes should_split_on only returns true for single-byte chars
        }
    }

    Ok(())
}

fn should_split_on(c: char) -> bool {
    c == '.'
}

fn is_diacritic(x: char) -> bool {
    '\u{0300}' <= x && x <= '\u{036f}'
}

fn normalize_into(segment: &str, buf: &mut String) {
    buf.clear();

    for x in segment.nfd() {
        if is_diacritic(x) {
            continue;
        }
        if x.is_ascii() {
            buf.push(x.to_ascii_lowercase());
        } else {
            buf.extend(x.to_lowercase());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_normalizes_segment() {
        let mut buf = String::new();
        normalize_into("DïācRîtįcs", &mut buf);
        assert_eq!(buf, "diacritics");
    }

    extern "C" fn token_callback(
        ctx: *mut c_void,
        flags: c_int,
        token: *const c_char,
        token_len: c_int,
        start: c_int,
        end: c_int,
    ) -> c_int {
        assert_eq!(flags, 0);

        let tokens_ptr = ctx as *mut _ as *mut Vec<(String, c_int, c_int)>;
        let tokens = unsafe { tokens_ptr.as_mut() }.expect("tokens pointer");
        let slice =
            unsafe { core::slice::from_raw_parts(token as *const c_uchar, token_len as usize) };
        let token = String::from_utf8(slice.to_vec()).expect("Expected utf-8 token");

        tokens.push((token, start, end));

        return SQLITE_OK;
    }

    #[test]
    fn it_emits_segments() {
        let input = "hello world! 知识? 안녕 세상";
        let mut tokens: Vec<(String, c_int, c_int)> = vec![];
        signal_fts5_tokenize_internal(
            &mut tokens as *mut _ as *mut c_void,
            input.as_bytes().as_ptr() as *const c_char,
            input.len() as i32,
            token_callback,
        )
        .expect("tokenize internal should not fail");

        assert_eq!(
            tokens,
            [
                ("hello", 0, 5),
                ("world", 6, 11),
                ("知", 13, 16),
                ("识", 16, 19),
                ("안녕", 21, 27),
                ("세상", 28, 34)
            ]
            .map(|(s, start, end)| (s.to_owned(), start, end))
        );
    }

    #[test]
    fn it_splits_on_dot() {
        let input = "a.b.c";
        let mut tokens: Vec<(String, c_int, c_int)> = vec![];
        signal_fts5_tokenize_internal(
            &mut tokens as *mut _ as *mut c_void,
            input.as_bytes().as_ptr() as *const c_char,
            input.len() as i32,
            token_callback,
        )
        .expect("tokenize internal should not fail");

        assert_eq!(
            tokens,
            [("a", 0, 1), ("b", 2, 3), ("c", 4, 5),].map(|(s, start, end)| (s.to_owned(), start, end))
        );
    }

    #[test]
    fn it_splits_on_at() {
        let input = "a@b";
        let mut tokens: Vec<(String, c_int, c_int)> = vec![];
        signal_fts5_tokenize_internal(
            &mut tokens as *mut _ as *mut c_void,
            input.as_bytes().as_ptr() as *const c_char,
            input.len() as i32,
            token_callback,
        )
            .expect("tokenize internal should not fail");

        assert_eq!(
            tokens,
            [("a", 0, 1), ("b", 2, 3)].map(|(s, start, end)| (s.to_owned(), start, end))
        );
    }

    #[test]
    fn it_ignores_invalid_utf8() {
        let input = b"\xc3\x28";
        let mut tokens: Vec<(String, c_int, c_int)> = vec![];

        assert_eq!(
            signal_fts5_tokenize_internal(
                &mut tokens as *mut _ as *mut c_void,
                input.as_ptr() as *const c_char,
                input.len() as i32,
                token_callback,
            )
            .expect_err("tokenize internal should not fail"),
            SQLITE_OK
        );

        assert_eq!(tokens, []);
    }
}
