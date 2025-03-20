mod char_flags;

pub use self::char_flags::*;

const NON: CharFlags = CharFlags::NONE;
const WWW: CharFlags = CharFlags::WINDOWS;
const WWM: CharFlags = CharFlags::from_bits_retain(6);
const UWM: CharFlags = CharFlags::from_bits_retain(7);
const WEE: CharFlags = CharFlags::WINDOWS_END;

const CHAR_MAP: &[CharFlags] = &[
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

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
    "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6",
    "LPT7", "LPT8", "LPT9",
];

const UNIX_RESERVED: &[&str] = &[".", ".."];

/// Checks if the given char is allowed in path on the given systems.
pub fn allowed(c: char, mode: CharFlags) -> bool {
    let n = c as u32 as usize;
    if n >= CHAR_MAP.len() {
        true
    } else {
        !CHAR_MAP[n].intersects(mode)
    }
}

/// Escape the given string so that it may be used as valid path on the given
/// systems.
pub fn escape_str(mut p: &str, esc: char, mode: CharFlags) -> String {
    let mut res = String::new();

    if mode.contains(CharFlags::WINDOWS) {
        if let Some((s, r)) = p.rsplit_once('.') {
            if WINDOWS_RESERVED.contains(&s) {
                res.push(esc);
            }
            res += s;
            p = r;
        } else {
            if WINDOWS_RESERVED.contains(&p) {
                res.push(esc);
            }
            return res + p;
        }
    }

    if res.is_empty() && mode.intersects(CharFlags::UNIX | CharFlags::MAC) {
        if UNIX_RESERVED.contains(&p) {
            res.push(esc);
            return res + p;
        }
    }

    for c in p.chars() {
        if c == esc || !allowed(c, mode) {
            res.push(esc);
            res += &format!("{:2x}", c as u32);
        }
    }

    if mode.intersects(CharFlags::WINDOWS) {
        if let Some(c) = res.pop() {
            if !allowed(c, CharFlags::WINDOWS_END) {
                res.push(esc);
                res += &format!("{:2x}", c as u32);
            } else {
                res.push(c);
            }
        }
    }

    todo!()
}
