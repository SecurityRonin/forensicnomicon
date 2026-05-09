/// Dataset variants — one per 1–9 key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dataset {
    Catalog = 0,
    Lolbas = 1,
    WindowsCmdlets = 2,
    WindowsMmc = 3,
    WindowsWmi = 4,
    AbusableSites = 5,
    Playbooks = 6,
}

impl Dataset {
    pub fn from_idx(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::Catalog),
            1 => Some(Self::Lolbas),
            2 => Some(Self::WindowsCmdlets),
            3 => Some(Self::WindowsMmc),
            4 => Some(Self::WindowsWmi),
            5 => Some(Self::AbusableSites),
            6 => Some(Self::Playbooks),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Catalog => "catalog",
            Self::Lolbas => "lolbas",
            Self::WindowsCmdlets => "cmdlets",
            Self::WindowsMmc => "mmc",
            Self::WindowsWmi => "wmi",
            Self::AbusableSites => "abusable sites",
            Self::Playbooks => "playbooks",
        }
    }
}
