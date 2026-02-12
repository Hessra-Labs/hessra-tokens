/// TokenTimeConfig allows control over token creation times and durations
/// This is used to create tokens with custom start times and durations
/// for testing purposes. In the future, this can be enhanced to support
/// variable length tokens, such as long-lived bearer tokens.
#[derive(Debug, Clone, Copy)]
pub struct TokenTimeConfig {
    /// Optional custom start time (now time override)
    pub start_time: Option<i64>,
    /// Duration in seconds (default: 300 seconds = 5 minutes)
    pub duration: i64,
}

impl Default for TokenTimeConfig {
    fn default() -> Self {
        Self {
            start_time: None,
            duration: 300, // 5 minutes in seconds
        }
    }
}
