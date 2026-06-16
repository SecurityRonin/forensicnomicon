use crate::threat_intel::profile::MalwareProfile;

mod azazel;
mod bdvl;
mod beurk;
mod diamorphine;
mod father;
mod jynx;
mod ld_preload_generic;
mod libprocesshider;
mod lkm_generic;
mod medusa;
mod necro;
mod prism;
mod reptile;
mod syslogk;
mod umbreon;
mod xmrig;

pub use azazel::AZAZEL;
pub use bdvl::BDVL;
pub use beurk::BEURK;
pub use diamorphine::DIAMORPHINE;
pub use father::FATHER;
pub use jynx::JYNX;
pub use ld_preload_generic::LD_PRELOAD_GENERIC;
pub use libprocesshider::LIB_PROCESS_HIDER;
pub use lkm_generic::LKM_GENERIC;
pub use medusa::MEDUSA;
pub use necro::NECRO;
pub use prism::PRISM;
pub use reptile::REPTILE;
pub use syslogk::SYSLOGK;
pub use umbreon::UMBREON;
pub use xmrig::XMRIG;

pub static ALL_PROFILES: &[&MalwareProfile] = &[
    &FATHER,
    &JYNX,
    &AZAZEL,
    &BDVL,
    &LIB_PROCESS_HIDER,
    &XMRIG,
    &LKM_GENERIC,
    &LD_PRELOAD_GENERIC,
    &UMBREON,
    &REPTILE,
    &DIAMORPHINE,
    &NECRO,
    &MEDUSA,
    &SYSLOGK,
    &BEURK,
    &PRISM,
];
