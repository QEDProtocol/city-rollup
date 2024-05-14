use std::time::Instant;
const TIME_LONG: &str = "\x1b[48;5;124m";
const TIME_MEDIUM: &str = "\x1b[48;5;24m";
const TIME_FAST: &str = "\x1B[38;5;230m\x1b[48;5;34m";
fn get_time_color(elapsed_ms: u64) -> &'static str {
    if elapsed_ms > 2000 {
        TIME_LONG
    } else if elapsed_ms > 500 {
        TIME_MEDIUM
    } else {
        TIME_FAST
    }
}
pub struct DebugTimer {
    pub start_time: Instant,
    pub name: String,
}
impl DebugTimer {
    pub fn new(name: &str) -> Self {
        let n = name.to_string();
        Self {
            start_time: Instant::now(),
            name: n,
        }
    }
    pub fn lap(&mut self, event_name: &str) -> u64 {
        let elapsed = self.start_time.elapsed();
        let elapsed_ms = elapsed.as_millis() as u64;
        println!(
            "\x1b[96m{}\x1b[0m - \x1b[94m{}\x1b[0m: {} {}ms \x1b[0m",
            self.name,
            event_name,
            get_time_color(elapsed_ms),
            elapsed_ms
        );
        self.start_time = Instant::now();
        elapsed_ms
    }
}
