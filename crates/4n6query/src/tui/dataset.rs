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
    MalwareProfiles = 7,
    AttackFlow = 8,
    EventIds = 9,
    Sigma = 10,
    Persistence = 11,
    RemoteAccess = 12,
    Drivers = 13,
    ThreatIndicators = 14,
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
            7 => Some(Self::MalwareProfiles),
            8 => Some(Self::AttackFlow),
            9 => Some(Self::EventIds),
            10 => Some(Self::Sigma),
            11 => Some(Self::Persistence),
            12 => Some(Self::RemoteAccess),
            13 => Some(Self::Drivers),
            14 => Some(Self::ThreatIndicators),
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
            Self::MalwareProfiles => "malware profiles",
            Self::AttackFlow => "attack flows",
            Self::EventIds => "event ids",
            Self::Sigma => "sigma",
            Self::Persistence => "persistence",
            Self::RemoteAccess => "remote access",
            Self::Drivers => "byovd drivers",
            Self::ThreatIndicators => "threat indicators",
        }
    }
}
