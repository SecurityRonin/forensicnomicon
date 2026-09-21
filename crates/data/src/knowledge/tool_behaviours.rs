//! Static [`ToolBehaviour`] instances and the [`TOOL_BEHAVIOURS`] slice.

use super::ToolBehaviour;

/// Every registered tool behaviour. Lookup and iteration read this slice;
/// a static not referenced here is invisible to every consumer.
pub static TOOL_BEHAVIOURS: &[ToolBehaviour] = &[];
