use std::time::Instant;

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
            "\x1b[96m{}\x1b[0m - \x1b[94m{}\x1b[0m: \x1b[101m{}ms\x1b[0m",
            self.name, event_name, elapsed_ms
        );
        self.start_time = Instant::now();
        elapsed_ms
    }
}
