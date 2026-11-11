//! Filename sanitizer.
//!
//! Given a filename, uniquely escape the filename so that it is allowed by the
//! OS.
//!
//! Supported OS:
//! - Windows
//! - Linux (unix)
//! - MAC
//!
//! The main function ofthis crate is [`sanitize`]. It escapes the string
//! in a way that is supported by all supported platforms and guarantees that
//! unique inputs will result in unique outpus:
//!
//! ```
//! use filesan::sanitize;
//!
//! assert_eq!(
//!     sanitize("\x00hello/the_re.txt:."),
//!     "_00hello_2Fthe_5Fre.txt_3A_2E"
//! );
//! ```
//!
//! For all of the functions in this crate there exists a variant that returns
//! and variant that appends to allocated string ending with `_to` (e.g.
//! [`sanitize_to`])
//!
//! If you need more control, you can use [`escape_str`] or [`replace_escape`]
//! which will take string as input, and return modified version that can be
//! used as filename:
//! ```
//! use filesan::{escape_str, Mode};
//!
//! // Unix support
//! assert_eq!(
//!     escape_str("\x00hello/the_re.txt:.", '_', Mode::UNIX),
//!     "_00hello_2Fthe_5Fre.txt:."
//! );
//!
//! // Windows support
//! assert_eq!(
//!     escape_str("\x00hello/the_re.txt:.", '_', Mode::WINDOWS),
//!     "_00hello_2Fthe_5Fre.txt_3A_2E"
//! );
//!
//! // MACOS support
//! assert_eq!(
//!     escape_str("\x00hello/the_re.txt:.", '_', Mode::MAC),
//!     "_00hello_2Fthe_5Fre.txt_3A."
//! );
//! ```
//!
//! You can use [`Mode::SYSTEM`] to get your current target system. See
//! documentation of [`escape_str`] and [`replace_escape`] for more info.
//!
//! Although this crate provides the capability of escaping filenames only for
//! certain systems, it is recommended to always use the [`Mode::ALL`] so that
//! the generated filenames are transferable to any system.

use std::fmt::Write;

mod char_flags;

pub use self::char_flags::*;

const NON: Mode = Mode::NONE;
const WWW: Mode = Mode::WINDOWS;
const WWM: Mode =
    Mode::from_bits_retain(Mode::WINDOWS.bits() | Mode::MAC.bits());
const UWM: Mode = Mode::from_bits_retain(
    Mode::UNIX.bits() | Mode::WINDOWS.bits() | Mode::MAC.bits(),
);
const WEE: Mode = Mode::WINDOWS_END;

const DISALLOWED_CHARS: &[Mode] = &[
    // NUL SOH STX ETX  EOT  ENQ  ACK  BEL  BS   TAB  LF   VT   FF   CR   SO
    UWM, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW,
    // SI DLE DC1  DC2  DC3  DC4  NAK  SYN  ETB  CAN  EM   SUB  ESC  FS   GS
    UWM, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW, WWW,
    // RS US  SP   !    "    #    $    %    &    '    (    )    *    +    ,
    WWW, WWW, WEE, NON, WWW, NON, NON, NON, NON, NON, NON, NON, WWW, NON, NON,
    // - .    /    0    1    2    3    4    5    6    7    8    9    :    ;
    NON, WEE, UWM, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, WWM, NON,
    // < =    >    ?    @    A    B    C    D    E    F    G    H    I    J
    WWW, NON, WWW, WWW, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON,
    // K L    M    N    O    P    Q    R    S    T    U    V    W    X    Y
    NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON,
    // Z [    \    ]    ^    _    `    a    b    c    d    e    f    g    h
    NON, NON, WWW, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON,
    // i j    k    l    m    n    o    p    q    r    s    t    u    v    w
    NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON, NON,
    // x y    z    {    |    }    ~    DEL
    NON, NON, NON, NON, WWW, NON, NON, NON,
];

/// Reserved filenames on windows.
pub const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
    "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
    "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Reserved filenames on unix.
pub const UNIX_RESERVED: &[&str] = &[".", ".."];

/// Reserved filenames on the current target system (unix).
#[cfg(unix)]
pub const SYSTEM_RESERVED: &[&str] = UNIX_RESERVED;
/// Reserved filenames on the current target system (windows).
#[cfg(windows)]
pub const SYSTEM_RESERVED: &[&str] = WINDOWS_RESERVED;
/// Reserved filenames on the current target system (mac).
#[cfg(target_os = "macos")]
pub const SYSTEM_RESERVED: &[&str] = UNIX_RESERVED;

/// Checks if the given char is allowed in path on the given systems.
///
/// Disallowed characters by mode:
/// - [`Mode::UNIX`]: `\x00`, `/`
/// - [`Mode::WINDOWS`]: `0x00` - `0x31`, `<`, `>`, `:`, `"`, `/`, `\`,
///   `|`, `?`, `*`
/// - [`Mode::MAC`]: `\x00`, `/`, `:`
/// - [`Mode::ALL`]: all of the above.
/// - [`Mode::SYSTEM`]: flag of the current target system.
/// - [`Mode::WINDOWS_END`]: ` `, `.`
pub fn allowed(c: char, mode: Mode) -> bool {
    let n = c as u32 as usize;
    if n >= DISALLOWED_CHARS.len() {
        true
    } else {
        !DISALLOWED_CHARS[n].intersects(mode)
    }
}

/// Sanitize the given string so that it may be used as valid path on any
/// of the supported systems (Unix (Linux), Windows and MacOS).
///
/// If you want to append to already allocated string, use
/// [`sanitize_to`].
///
/// This is the general function that you should use when you are unsure. If
/// you want more control, see [`escape_str`] and [`replace_escape`].
///
/// It is guaranteed that unique inputs to this function will generate unique
/// outputs, and the same inputs will generate the same outputs.
///
/// This is equivalent to calling `escape_str(p, '_', Mode::ALL)`:
/// - disallowed characters `0x00` - `0x31`, `<`, `>`, `:`, `"`, `/`, `\`, `|`,
///   `?`, `*`
/// - disallowed filenames (both with and without extension): `CON`, `PRN`,
///   `AUX`, `NUL`, `COM1` - `COM9`, `LPT1` - `LPT9`
/// - disallowed characters at the end: ` `, `.`
///
/// # Returns
/// String with escaped invalid paths. Escape character and invalid characters
/// are replaced with escape character followed by two digit hex value of the
/// character. Invalid filenames are prefixed with the escape character.
///
/// # Example
/// ```
/// use filesan::sanitize;
///
/// assert_eq!(
///     sanitize("\x00hello/the_re.txt:."),
///     "_00hello_2Fthe_5Fre.txt_3A_2E"
/// );
/// ```
pub fn sanitize(p: impl AsRef<str>) -> String {
    escape_str(p, '_', Mode::ALL)
}

/// Sanitize the given string so that it may be used as valid path on any
/// of the supported systems (Unix (Linux), Windows and MacOS) and append it
/// to the given string.
///
/// This is the general function that you should use when you are unsure. If
/// you want more control, see [`escape_str`] and [`replace_escape`].
///
/// It is guaranteed that unique inputs to this function will generate unique
/// outputs, and the same inputs will generate the same outputs.
///
/// This is equivalent to calling `escape_str(p, '_', Mode::ALL)`:
/// - disallowed characters `0x00` - `0x31`, `<`, `>`, `:`, `"`, `/`, `\`, `|`,
///   `?`, `*`
/// - disallowed filenames (both with and without extension): `CON`, `PRN`,
///   `AUX`, `NUL`, `COM1` - `COM9`, `LPT1` - `LPT9`
/// - disallowed characters at the end: ` `, `.`
///
/// # Returns
/// String with escaped invalid paths. Escape character and invalid characters
/// are replaced with escape character followed by two digit hex value of the
/// character. Invalid filenames are prefixed with the escape character.
pub fn sanitize_to(p: impl AsRef<str>, out: &mut String) {
    escape_str_to(p, '_', Mode::ALL, out)
}

/// Escape the given string so that it may be used as valid path on the given
/// systems.
///
/// If you want to append to already allocated string, use
/// [`escape_str_to`].
///
/// It is guaranteed that unique inputs to this function will generate unique
/// outputs, and the same inputs will generate the same outputs.
///
/// The escape character may be any character that you are sure that is valid
/// in filename on the target OS. Good choice is for example the character `_`.
///
/// `mode` may be any combination of the following flags that combine features
/// of disallowed filename features that will be escaped:
/// - [`Mode::UNIX`]:
///     - disallowed characters: `\x00`, `/`
///     - disallowed filenames: `.`, `..`
/// - [`Mode::WINDOWS`]:
///     - disallowed characters `0x00` - `0x31`, `<`, `>`, `:`, `"`, `/`, `\`,
///       `|`, `?`, `*`
///     - disallowed filenames (both with and without extension): `CON`, `PRN`,
///       `AUX`, `NUL`, `COM1` - `COM9`, `LPT1` - `LPT9`
///     - disallowed characters at the end: ` `, `.`
/// - [`Mode::MAC`]:
///     - disallowed characters: `\x00`, `/`, `:`
///     - disallowed filenames: `.`, `..`
/// - [`Mode::ALL`]: all of the above.
/// - [`Mode::SYSTEM`]: flag of the current target system.
/// - [`Mode::WINDOWS_END`]:
///     - disallowed characters: ` `, `.`
///
/// # Returns
/// String with escaped invalid paths. Escape character and invalid characters
/// are replaced with escape character followed by two digit hex value of the
/// character. Invalid filenames are prefixed with the escape character.
///
/// # Example
/// ```
/// use filesan::{escape_str, Mode};
///
/// // Unix support
/// assert_eq!(
///     escape_str("\x00hello/the_re.txt:.", '_', Mode::UNIX),
///     "_00hello_2Fthe_5Fre.txt:."
/// );
///
/// // Windows support
/// assert_eq!(
///     escape_str("\x00hello/the_re.txt:.", '_', Mode::WINDOWS),
///     "_00hello_2Fthe_5Fre.txt_3A_2E"
/// );
///
/// // MACOS support
/// assert_eq!(
///     escape_str("\x00hello/the_re.txt:.", '_', Mode::MAC),
///     "_00hello_2Fthe_5Fre.txt_3A."
/// );
/// ```
pub fn escape_str(p: impl AsRef<str>, esc: char, mode: Mode) -> String {
    let mut res = String::new();
    escape_str_to(p, esc, mode, &mut res);
    res
}

/// Escape the given string so that it may be used as valid path on the given
/// systems and append it to the given string.
///
/// It is guaranteed that unique inputs to this function will generate unique
/// outputs, and the same inputs will generate the same outputs.
///
/// The escape character may be any character that you are sure that is valid
/// in filename on the target OS. Good choice is for example the character `_`.
///
/// `mode` may be any combination of the following flags that combine features
/// of disallowed filename features that will be escaped:
/// - [`Mode::UNIX`]:
///     - disallowed characters: `\x00`, `/`
///     - disallowed filenames: `.`, `..`
/// - [`Mode::WINDOWS`]:
///     - disallowed characters `0x00` - `0x31`, `<`, `>`, `:`, `"`, `/`, `\`,
///       `|`, `?`, `*`
///     - disallowed filenames (both with and without extension): `CON`, `PRN`,
///       `AUX`, `NUL`, `COM1` - `COM9`, `LPT1` - `LPT9`
///     - disallowed characters at the end: ` `, `.`
/// - [`Mode::MAC`]:
///     - disallowed characters: `\x00`, `/`, `:`
///     - disallowed filenames: `.`, `..`
/// - [`Mode::ALL`]: all of the above.
/// - [`Mode::SYSTEM`]: flag of the current target system.
/// - [`Mode::WINDOWS_END`]:
///     - disallowed characters: ` `, `.`
///
/// # Returns
/// String with escaped invalid paths. Escape character and invalid characters
/// are replaced with escape character followed by two digit hex value of the
/// character. Invalid filenames are prefixed with the escape character.
pub fn escape_str_to(
    p: impl AsRef<str>,
    esc: char,
    mode: Mode,
    out: &mut String,
) {
    escape_str_inner(
        p,
        esc,
        mode,
        |res, chr| _ = write!(res, "{esc}{:02X}", chr as u32),
        |res, s| {
            res.push(esc);
            let Some(c) = s.chars().next() else {
                return;
            };
            _ = write!(res, "{:02X}", c as u32);
            *res += &s[c.len_utf8()..];
        },
        out,
    );
}

/// Escape the given string so that it may be used as valid path on the given
/// systems.
///
/// If you want to append to already allocated string, use
/// [`replace_escape_to`].
///
/// The new string will be formed by replacing some characters by the escape
/// character. So the final strin will have the same amount of characters as
/// the original.
///
/// The escape character may be any character that you are sure that is valid
/// in filename on the target OS. Other bad options are `.` and ` ` (space).
/// Good choice is for example the character `_`.
///
/// `mode` may be any combination of the following flags that combine features
/// of disallowed filename features that will be escaped:
/// - [`Mode::UNIX`]:
///     - disallowed characters: `\x00`, `/`
///     - disallowed filenames: `.`, `..`
/// - [`Mode::WINDOWS`]:
///     - disallowed characters `0x00` - `0x31`, `<`, `>`, `:`, `"`, `/`, `\`,
///       `|`, `?`, `*`
///     - disallowed filenames (both with and without extension): `CON`, `PRN`,
///       `AUX`, `NUL`, `COM1` - `COM9`, `LPT1` - `LPT9`
///     - disallowed characters at the end: ` `, `.`
/// - [`Mode::MAC`]:
///     - disallowed characters: `\x00`, `/`, `:`
///     - disallowed filenames: `.`, `..`
/// - [`Mode::ALL`]: all of the above.
/// - [`Mode::SYSTEM`]: flag of the current target system.
/// - [`Mode::WINDOWS_END`]:
///     - disallowed characters: ` `, `.`
///
/// # Returns
/// String with escaped invalid paths. Escape character and invalid characters
/// are replaced with escape character followed by two digit hex value of the
/// character. Invalid filenames are prefixed with the escape character.
///
/// # Example
/// ```
/// use filesan::{replace_escape, Mode};
///
/// // Unix support
/// assert_eq!(
///     replace_escape("\x00hello/the_re.txt:.", '_', Mode::UNIX),
///     "_hello_the_re.txt:."
/// );
///
/// // Windows support
/// assert_eq!(
///     replace_escape("\x00hello/the_re.txt:.", '_', Mode::WINDOWS),
///     "_hello_the_re.txt__"
/// );
///
/// // MACOS support
/// assert_eq!(
///     replace_escape("\x00hello/the_re.txt:.", '_', Mode::MAC),
///     "_hello_the_re.txt_."
/// );
/// ```
pub fn replace_escape(p: &str, esc: char, mode: Mode) -> String {
    let mut res = String::new();
    replace_escape_to(p, esc, mode, &mut res);
    res
}

/// Escape the given string so that it may be used as valid path on the given
/// systems and append the result to the given string.
///
/// The new string will be formed by replacing some characters by the escape
/// character. So the final strin will have the same amount of characters as
/// the original.
///
/// The escape character may be any character that you are sure that is valid
/// in filename on the target OS. Other bad options are `.` and ` ` (space).
/// Good choice is for example the character `_`.
///
/// `mode` may be any combination of the following flags that combine features
/// of disallowed filename features that will be escaped:
/// - [`Mode::UNIX`]:
///     - disallowed characters: `\x00`, `/`
///     - disallowed filenames: `.`, `..`
/// - [`Mode::WINDOWS`]:
///     - disallowed characters `0x00` - `0x31`, `<`, `>`, `:`, `"`, `/`, `\`,
///       `|`, `?`, `*`
///     - disallowed filenames (both with and without extension): `CON`, `PRN`,
///       `AUX`, `NUL`, `COM1` - `COM9`, `LPT1` - `LPT9`
///     - disallowed characters at the end: ` `, `.`
/// - [`Mode::MAC`]:
///     - disallowed characters: `\x00`, `/`, `:`
///     - disallowed filenames: `.`, `..`
/// - [`Mode::ALL`]: all of the above.
/// - [`Mode::SYSTEM`]: flag of the current target system.
/// - [`Mode::WINDOWS_END`]:
///     - disallowed characters: ` `, `.`
///
/// # Returns
/// String with escaped invalid paths. Escape character and invalid characters
/// are replaced with escape character followed by two digit hex value of the
/// character. Invalid filenames are prefixed with the escape character.
pub fn replace_escape_to(p: &str, esc: char, mode: Mode, out: &mut String) {
    escape_str_inner(
        p,
        esc,
        mode,
        |res, _| res.push(esc),
        |res, mut s| {
            while let Some(post) = s.strip_prefix(esc) {
                s = post;
                res.push(esc);
            }
            if !s.is_empty() {
                res.push(esc);
                *res += &s[1..];
            }
        },
        out,
    );
}

fn escape_str_inner(
    p: impl AsRef<str>,
    esc: char,
    mode: Mode,
    mut chr: impl FnMut(&mut String, char),
    mut name: impl FnMut(&mut String, &str),
    res: &mut String,
) {
    let mut p = p.as_ref();
    res.reserve(p.len());

    if mode.contains(Mode::WINDOWS) {
        if let Some((s, r)) = p.rsplit_once('.') {
            if windows_reserved_contains(s) {
                name(res, s);
                res.push('.');
                p = r;
            }
        } else if windows_reserved_contains(p) {
            name(res, p);
            return;
        }
    }

    if res.is_empty()
        && mode.intersects(Mode::UNIX | Mode::MAC)
        && UNIX_RESERVED.contains(&p)
    {
        name(res, p);
        p = "";
    }

    for c in p.chars() {
        if c == esc || !allowed(c, mode) {
            chr(res, c);
        } else {
            res.push(c);
        }
    }

    if mode.intersects(Mode::WINDOWS)
        && let Some(c) = res.pop()
    {
        if !allowed(c, Mode::WINDOWS_END) {
            chr(res, c);
        } else {
            res.push(c);
        }
    }
}

fn windows_reserved_contains(s: &str) -> bool {
    match s.len() {
        3 => ["CON", "PRN", "AUX", "NUL"]
            .iter()
            .any(|o| s.eq_ignore_ascii_case(o)),
        4 => {
            let s = &s[..s.floor_char_boundary(3)];
            s.eq_ignore_ascii_case("COM") || s.eq_ignore_ascii_case("LPT")
        }
        _ => false,
    }
}
