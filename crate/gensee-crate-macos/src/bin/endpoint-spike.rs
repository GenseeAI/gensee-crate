use gensee_crate_macos::endpoint::{
    EXEC_EVENT_TYPES, FILE_MUTATION_EVENT_TYPES, FILE_OPEN_EVENT_TYPES,
};
use std::env;
use std::io;
use std::process::Command;
use std::time::{Duration, Instant};

fn main() {
    if let Err(error) = run() {
        eprintln!("endpoint-spike: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("exec") => run_eslogger("exec", EXEC_EVENT_TYPES, &args[1..]),
        Some("file-mutation") => {
            run_eslogger("file-mutation", FILE_MUTATION_EVENT_TYPES, &args[1..])
        }
        Some("file-open") | Some("sensitive-open") => {
            run_eslogger("file-open", FILE_OPEN_EVENT_TYPES, &args[1..])
        }
        Some("all") => {
            let mut events = Vec::new();
            events.extend_from_slice(EXEC_EVENT_TYPES);
            events.extend_from_slice(FILE_MUTATION_EVENT_TYPES);
            events.extend_from_slice(FILE_OPEN_EVENT_TYPES);
            run_eslogger("all", &events, &args[1..])
        }
        Some("list") => {
            print_plan();
            Ok(())
        }
        Some("--help") | Some("-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown endpoint-spike mode: {other}"),
        )),
    }
}

struct SpikeOptions {
    eslogger_args: Vec<String>,
    duration: Option<Duration>,
}

fn run_eslogger(mode: &str, events: &[&str], extra_args: &[String]) -> io::Result<()> {
    let options = parse_spike_options(extra_args)?;

    eprintln!("endpoint-spike: mode={mode}");
    eprintln!("endpoint-spike: using /usr/bin/eslogger as temporary ES source");
    eprintln!("endpoint-spike: events={}", events.join(","));
    eprintln!("endpoint-spike: run with sudo if eslogger cannot subscribe.");
    if let Some(duration) = options.duration {
        eprintln!("endpoint-spike: stopping after {}s", duration.as_secs());
    }

    let mut command = Command::new("/usr/bin/eslogger");
    command.arg("--format").arg("json");
    for arg in &options.eslogger_args {
        command.arg(arg);
    }
    for event in events {
        command.arg(event);
    }

    let mut child = command.spawn()?;
    let (status, timed_out) = if let Some(duration) = options.duration {
        wait_with_duration(&mut child, duration)?
    } else {
        (child.wait()?, false)
    };
    if timed_out {
        eprintln!("endpoint-spike: duration reached; stopped eslogger");
        Ok(())
    } else if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "eslogger exited with status {status}"
        )))
    }
}

fn parse_spike_options(args: &[String]) -> io::Result<SpikeOptions> {
    let mut eslogger_args = Vec::new();
    let mut duration = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--duration-seconds" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--duration-seconds requires a value",
                    ));
                };
                let seconds = value.parse::<u64>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--duration-seconds must be a positive integer",
                    )
                })?;
                duration = Some(Duration::from_secs(seconds));
                index += 2;
            }
            arg => {
                eslogger_args.push(arg.to_string());
                index += 1;
            }
        }
    }

    Ok(SpikeOptions {
        eslogger_args,
        duration,
    })
}

fn wait_with_duration(
    child: &mut std::process::Child,
    duration: Duration,
) -> io::Result<(std::process::ExitStatus, bool)> {
    let started = Instant::now();

    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((status, false));
        }
        if started.elapsed() >= duration {
            child.kill()?;
            return child.wait().map(|status| (status, true));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn print_plan() {
    println!("exec events: {}", EXEC_EVENT_TYPES.join(", "));
    println!(
        "file mutation events: {}",
        FILE_MUTATION_EVENT_TYPES.join(", ")
    );
    println!(
        "file open/read events: {}",
        FILE_OPEN_EVENT_TYPES.join(", ")
    );
}

fn print_usage() {
    println!("Endpoint Security spike");
    println!();
    println!("USAGE:");
    println!("  cargo run -p gensee-crate-macos --bin endpoint-spike -- list");
    println!("  cargo run -p gensee-crate-macos --bin endpoint-spike -- exec");
    println!(
        "  cargo run -p gensee-crate-macos --bin endpoint-spike -- exec --select /bin/sleep --duration-seconds 10"
    );
    println!("  cargo run -p gensee-crate-macos --bin endpoint-spike -- file-mutation");
    println!("  cargo run -p gensee-crate-macos --bin endpoint-spike -- file-open");
    println!("  cargo run -p gensee-crate-macos --bin endpoint-spike -- all --select /path/prefix");
    println!(
        "  sudo cargo run -p gensee-crate-macos --bin endpoint-spike -- exec | GENSEE_HOME=$PWD/.gensee-dev ./target/debug/gensee ingest eslogger"
    );
    println!();
    println!("This is a temporary spike around Apple's eslogger. Production should move");
    println!("to a signed EndpointSecurity client/system extension with auth/notify policy.");
    println!("exec is system-wide; prefer --select while testing to reduce background noise.");
    println!("use --duration-seconds during piped tests so the stream closes cleanly.");
}
