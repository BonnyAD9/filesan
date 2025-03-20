use bitflags::bitflags;

bitflags! {
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct CharFlags: u32 {
        const NONE = 0x0;
        const UNIX = 0x1;
        const WINDOWS = 0x2;
        const MAC = 0x4;
        const WINDOWS_END = 0x8;
        #[cfg(unix)]
        const SYSTEM = Self::UNIX.bits();
        #[cfg(windows)]
        const SYSTEM = Self::WINDOWS.bits();
        #[cfg(target_os = "macos")]
        const SYSTEM = Self::MAC.bits();
    }
}
