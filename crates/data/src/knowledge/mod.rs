//! Assembled knowledge-layer instances (Roadmap §2) over the types defined in
//! `forensicnomicon_core::knowledge`.
//!
//! The core crate owns the *schema* ([`ToolBehaviour`] and friends); this
//! module owns the *entries*, mirroring the `catalog` split: stable engine in
//! core, fast-moving data here.
//!
//! Every entry is verified against an independent primary source — the tool's
//! own source code, issue tracker, release notes, or published research —
//! cited in `sources`. Where a behaviour is a documented consequence of the
//! tool's design (a list-walker missing an unlinked entry, an archived tool's
//! frozen structure definitions), the entry says so: a design limit filed as a
//! bug misleads as surely as a bug filed as a design limit.

pub use forensicnomicon_core::knowledge::{
    AntiForensicMethod, CorrelationHint, CorrelationRelation, ToolBehaviour, ToolBehaviourKind,
};

mod anti_forensic_methods;
mod tool_behaviours;

pub use anti_forensic_methods::ANTI_FORENSIC_METHODS;
pub use tool_behaviours::TOOL_BEHAVIOURS;

#[cfg(test)]
mod tests;
