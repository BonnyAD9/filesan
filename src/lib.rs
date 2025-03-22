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
//! as input, and return modified version that can be used as filename.

mod char_flags;

pub use self::char_flags::*;

const NON: CharFlags = CharFlags::NONE;
const WWW: CharFlags = CharFlags::WINDOWS;
const WWM: CharFlags = CharFlags::from_bits_retain(
    CharFlags::WINDOWS.bits() | CharFlags::MAC.bits(),
);
const UWM: CharFlags = CharFlags::from_bits_retain(
    CharFlags::UNIX.bits() | CharFlags::WINDOWS.bits() | CharFlags::MAC.bits(),
);
const WEE: CharFlags = CharFlags::WINDOWS_END;

const DISALLOWED_CHARS: &[CharFlags] = &[
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
pub fn allowed(c: char, mode: CharFlags) -> bool {
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
/// - [`CharFlags::UNIX`]:
///     - disallowed characters: `\x00`, `/`
///     - disallowed filenames: `.`, `..`
/// - [`CharFlags::WINDOWS`]:
///     - disallowed characters `0x00` - `0x31`, `<`, `>`, `:`, `"`, `/`, `\`,
///       `|`, `?`, `*`.
///     - disallowed filenames (both with and without extension): `CON`, `PRN`,
///       `AUX`, `NUL`, `COM1` - `COM9`, `LPT1` - `LPT9`
///     - disallowed characters at the end: ` `, `.`
/// - [`CharFlags::MAC`]:
///     - disallowed characters: `\x00`, `/`, `:`
///     - disallowed filenames: `.`, `..`
/// - [`CharFlags::ALL`]: all of the above.
/// - [`CharFlags::SYSTEM`]: flag of the current target system.
/// - [`CharFlags::WINDOWS_END`]:
///     - disallowed characters: ` `, `.`
///
/// # Returns
/// String with escaped invalid paths. Escape character and invalid characters
/// are replaced with escape character followed by two digit hex value of the
/// character. Invalid filenames are prefixed with the escape character.
pub fn escape_str(mut p: &str, esc: char, mode: CharFlags) -> String {
    let mut res = String::new();

    if mode.contains(CharFlags::WINDOWS) {
        if let Some((s, r)) = p.rsplit_once('.') {
            if WINDOWS_RESERVED.contains(&s) {
                res.push(esc);
                res += s;
                res.push('.');
                p = r;
            }
        } else {
            if WINDOWS_RESERVED.contains(&p) {
                res.push(esc);
                return res + p;
            }
        }
    }

    if res.is_empty()
        && mode.intersects(CharFlags::UNIX | CharFlags::MAC)
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

    if mode.intersects(CharFlags::WINDOWS) {
        if let Some(c) = res.pop() {
            if !allowed(c, CharFlags::WINDOWS_END) {
                res.push(esc);
                res += &format!("{:02X}", c as u32);
            } else {
                res.push(c);
            }
        }
    }

    res
}
