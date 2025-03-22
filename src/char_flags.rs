use bitflags::bitflags;

bitflags! {
    #[doc = "Escape flags for different systems. See documentation of"]
    #[doc = "[`crate::escape_str`] for more info."]
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct Mode: u32 {
        #[doc = "No system specific escapes."]
        const NONE = 0x0;
        #[doc = "Escapes specific to linux (unix)."]
        const UNIX = 0x1;
        #[doc = "Escapes specific to windows."]
        const WINDOWS = 0x2;
        #[doc = "Escapes specific to macos."]
        const MAC = 0x4;
        #[doc = "Escapes for all systems combined."]
        const ALL = 0x7;
        #[doc = "Disallowed characters at the end for windows. This is mostly"]
        #[doc = "for internal use."]
        const WINDOWS_END = 0x8;
        #[doc = "Escapes specific for the current target system (unix)."]
        #[cfg(unix)]
        const SYSTEM = Self::UNIX.bits();
        #[doc = "Escapes specific for the current target system (windows)."]
        #[cfg(windows)]
        const SYSTEM = Self::WINDOWS.bits();
        #[doc = "Escapes specific for the current target system (macos)."]
        #[cfg(target_os = "macos")]
        const SYSTEM = Self::MAC.bits();
    }
}
