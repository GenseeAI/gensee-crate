use super::*;
use gensee_crate_replay::{build_bundle, correlate_bundle, verify_bundle};

const REPLAY_USAGE: &str = "usage: gensee replay <build|verify|correlate> [options]\n\
       gensee replay build --manifest <manifest.json> --output <bundle-dir> [--signing-key <ed25519-seed.hex>]\n\
       gensee replay verify --bundle <bundle-dir> [--trusted-key <public-key.hex>] [--require-signature]\n\
       gensee replay correlate --bundle <bundle-dir> --rules <rules.json> --output <report.json> [--trusted-key <public-key.hex>] [--require-signature]";

pub(crate) fn handle_replay(mut args: Vec<OsString>) -> io::Result<()> {
    if args
        .iter()
        .any(|arg| matches!(arg.to_str(), Some("--help" | "-h")))
    {
        println!("{REPLAY_USAGE}");
        return Ok(());
    }
    let command = args
        .first()
        .and_then(|arg| arg.to_str())
        .ok_or_else(|| invalid_replay_args(REPLAY_USAGE))?
        .to_string();
    args.remove(0);
    match command.as_str() {
        "build" => replay_build(args),
        "verify" => replay_verify(args),
        "correlate" => replay_correlate(args),
        _ => Err(invalid_replay_args(REPLAY_USAGE)),
    }
}

fn replay_build(args: Vec<OsString>) -> io::Result<()> {
    let parsed = parse_replay_options(
        args,
        &["--manifest", "--output", "--signing-key"],
        &[],
        "gensee replay build",
    )?;
    let manifest = required_path(&parsed, "--manifest", "gensee replay build")?;
    let output = required_path(&parsed, "--output", "gensee replay build")?;
    let signing_key = parsed.values.get("--signing-key").map(PathBuf::from);
    let report = build_bundle(&manifest, &output, signing_key.as_deref())?;
    print_replay_json(&report)
}

fn replay_verify(args: Vec<OsString>) -> io::Result<()> {
    let parsed = parse_replay_options(
        args,
        &["--bundle", "--trusted-key"],
        &["--require-signature"],
        "gensee replay verify",
    )?;
    let bundle = required_path(&parsed, "--bundle", "gensee replay verify")?;
    let trusted_key = parsed.values.get("--trusted-key").map(PathBuf::from);
    let report = verify_bundle(
        &bundle,
        trusted_key.as_deref(),
        parsed.flags.contains("--require-signature"),
    )?;
    print_replay_json(&report)
}

fn replay_correlate(args: Vec<OsString>) -> io::Result<()> {
    let parsed = parse_replay_options(
        args,
        &["--bundle", "--rules", "--output", "--trusted-key"],
        &["--require-signature"],
        "gensee replay correlate",
    )?;
    let bundle = required_path(&parsed, "--bundle", "gensee replay correlate")?;
    let rules = required_path(&parsed, "--rules", "gensee replay correlate")?;
    let output = required_path(&parsed, "--output", "gensee replay correlate")?;
    let trusted_key = parsed.values.get("--trusted-key").map(PathBuf::from);
    let report = correlate_bundle(
        &bundle,
        &rules,
        &output,
        trusted_key.as_deref(),
        parsed.flags.contains("--require-signature"),
    )?;
    print_replay_json(&report)
}

#[derive(Default)]
struct ReplayOptions {
    values: BTreeMap<String, OsString>,
    flags: HashSet<String>,
}

fn parse_replay_options(
    args: Vec<OsString>,
    value_options: &[&str],
    flags: &[&str],
    command: &str,
) -> io::Result<ReplayOptions> {
    let mut parsed = ReplayOptions::default();
    let mut index = 0;
    while index < args.len() {
        let option = args[index]
            .to_str()
            .ok_or_else(|| invalid_replay_args(format!("{command}: arguments must be UTF-8")))?;
        if value_options.contains(&option) {
            let value = args.get(index + 1).ok_or_else(|| {
                invalid_replay_args(format!("{command}: {option} requires a value"))
            })?;
            if parsed
                .values
                .insert(option.to_string(), value.clone())
                .is_some()
            {
                return Err(invalid_replay_args(format!(
                    "{command}: duplicate option {option}"
                )));
            }
            index += 2;
        } else if flags.contains(&option) {
            if !parsed.flags.insert(option.to_string()) {
                return Err(invalid_replay_args(format!(
                    "{command}: duplicate flag {option}"
                )));
            }
            index += 1;
        } else {
            return Err(invalid_replay_args(format!(
                "{command}: unexpected argument {option}"
            )));
        }
    }
    Ok(parsed)
}

fn required_path(parsed: &ReplayOptions, option: &str, command: &str) -> io::Result<PathBuf> {
    parsed
        .values
        .get(option)
        .map(PathBuf::from)
        .ok_or_else(|| invalid_replay_args(format!("{command}: {option} is required")))
}

fn invalid_replay_args(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn print_replay_json(value: &impl serde::Serialize) -> io::Result<()> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    println!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_reject_duplicates_and_unknowns() {
        assert!(parse_replay_options(
            vec![
                "--bundle".into(),
                "one".into(),
                "--bundle".into(),
                "two".into()
            ],
            &["--bundle"],
            &[],
            "verify"
        )
        .is_err());
        assert!(parse_replay_options(vec!["--wat".into()], &[], &[], "verify").is_err());
    }
}
