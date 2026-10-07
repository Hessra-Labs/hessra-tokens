extern crate biscuit_auth as biscuit;

use biscuit::datalog::RunLimits;
use std::time::Duration;

/// Datalog execution budget for identity token verification and inspection.
///
/// Biscuit's default budget (1ms) is calibrated for native speed on an idle
/// machine; under WebAssembly or on a loaded CI runner the same evaluation
/// regularly exceeds it and verification fails spuriously. Identity tokens
/// are small and self-authored, so a generous fixed budget keeps the DoS
/// bound while working on every target.
pub(crate) fn datalog_limits() -> RunLimits {
    RunLimits {
        max_time: Duration::from_millis(50),
        ..Default::default()
    }
}
