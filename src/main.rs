
use rustest_coaps;

fn main() {
    if let Err(e) = rustest_coaps::run() {
        eprintln!("Error while pinging Google {}", e) // TODO: update when new functionality comes
    }
}
