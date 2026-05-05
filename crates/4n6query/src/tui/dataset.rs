/// Dataset variants — one per 1–9 key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dataset {
    Catalog = 0,
    WindowsLolbins = 1,
    LinuxLolbins = 2,
    MacosLolbins = 3,
    WindowsCmdlets = 4,
    WindowsMmc = 5,
    WindowsWmi = 6,
    AbusableSites = 7,
    Playbooks = 8,
}

impl Dataset {
    pub fn from_idx(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::Catalog),
            1 => Some(Self::WindowsLolbins),
            2 => Some(Self::LinuxLolbins),
            3 => Some(Self::MacosLolbins),
            4 => Some(Self::WindowsCmdlets),
            5 => Some(Self::WindowsMmc),
            6 => Some(Self::WindowsWmi),
            7 => Some(Self::AbusableSites),
            8 => Some(Self::Playbooks),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Catalog => "catalog",
            Self::WindowsLolbins => "windows lolbins",
            Self::LinuxLolbins => "linux lolbins",
            Self::MacosLolbins => "macos loobins",
            Self::WindowsCmdlets => "cmdlets",
            Self::WindowsMmc => "mmc",
            Self::WindowsWmi => "wmi",
            Self::AbusableSites => "abusable sites",
            Self::Playbooks => "playbooks",
        }
    }
}
