//! Filename sanitizer.
//!
//! Supported OS:
//! - Windows
//! - Linux (unix)
//! - MAC
//!
//! Given a filename, escape the filename so that it is allowed by the OS.
//!
//! The main function of this crate is [`escape_str`] which will take string
//! as input, and return modified version that can be used as filename:
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
//! documentation of [`escape_str`] for more info.

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

/// Escape the given string so that it may be used as valid path on the given
/// systems.
///
/// It is guaranteed that unique inputs to this function will generate unique
/// outputs.
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
pub fn escape_str(mut p: &str, esc: char, mode: Mode) -> String {
    let mut res = String::new();

    if mode.contains(Mode::WINDOWS) {
        if let Some((s, r)) = p.rsplit_once('.') {
            if WINDOWS_RESERVED.contains(&s) {
                res.push(esc);
                res += s;
                res.push('.');
                p = r;
            }
        } else if WINDOWS_RESERVED.contains(&p) {
            res.push(esc);
            return res + p;
        }
    }

    if res.is_empty()
        && mode.intersects(Mode::UNIX | Mode::MAC)
        && UNIX_RESERVED.contains(&p)
    {
        res.push(esc);
        return res + p;
    }

    for c in p.chars() {
        if c == esc || !allowed(c, mode) {
            res.push(esc);
            res += &format!("{:02X}", c as u32);
        } else {
            res.push(c);
        }
    }

    if mode.intersects(Mode::WINDOWS) {
        if let Some(c) = res.pop() {
            if !allowed(c, Mode::WINDOWS_END) {
                res.push(esc);
                res += &format!("{:02X}", c as u32);
            } else {
                res.push(c);
            }
        }
    }

    res
}
