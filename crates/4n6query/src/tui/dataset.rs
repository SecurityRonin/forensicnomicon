/// Dataset variants — one per 1–9 key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dataset {
    Catalog = 0,
    Lolbas = 1,
    AbusableSites = 2,
    WindowsCmdlets = 3,
    WindowsMmc = 4,
    WindowsWmi = 5,
    Playbooks = 6,
}

impl Dataset {
    pub fn from_idx(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::Catalog),
            1 => Some(Self::Lolbas),
            2 => Some(Self::AbusableSites),
            3 => Some(Self::WindowsCmdlets),
            4 => Some(Self::WindowsMmc),
            5 => Some(Self::WindowsWmi),
            6 => Some(Self::Playbooks),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Catalog => "catalog",
            Self::Lolbas => "lolbas",
            Self::AbusableSites => "abusable sites",
            Self::WindowsCmdlets => "cmdlets",
            Self::WindowsMmc => "mmc",
            Self::WindowsWmi => "wmi",
            Self::Playbooks => "playbooks",
        }
    }
}
