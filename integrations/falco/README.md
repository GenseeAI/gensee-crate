# Falco Linux system-event bridge

Gensee's Falco bridge captures a deliberately bounded kernel-event stream for
trajectory reconstruction while keeping enforcement and collection separate.
Falco observes selected process, file, network, and high-risk syscall events;
`gensee ingest falco` redacts and normalizes its JSON output into
`SystemEvent` records. Gensee extracts the Podman container ID from Falco's
built-in cgroup field and matches it to the local Tclone registry, attaching
the event to the corresponding source or fork run. This avoids a dependency on
Falco's optional container metadata plugin.

This is a capture layer, not a claim that Tclone is a confinement boundary.
The supplied `gensee-tclone-rules.yaml` rule pack records:

- process execution inside containers;
- opens under `/workspace` plus file mutation syscalls;
- connect, accept, bind, and listen activity;
- tracing, BPF, module, mount, namespace, and identity-changing syscalls.

It intentionally does not record read/write payload buffers, environment
variables, or every syscall. Command lines and Falco fields pass through the
same secret-redaction floor as other Gensee system-event sources.

## Deployment

Install Falco using the engine appropriate for the host kernel, enable JSON
stdout, load the Gensee rule pack, and pipe the event stream to the ingestor.
For example:

```bash
sudo falco \
  -r integrations/falco/gensee-tclone-rules.yaml \
  -o json_output=true \
  -o json_include_output_property=true \
  -o json_include_tags_property=true \
  -o stdout_output.enabled=true \
  -o syslog_output.enabled=false \
  | env GENSEE_HOME=/var/lib/gensee \
      gensee ingest falco --host "$(hostname)"
```

Run the ingestor as the same account that owns the selected `GENSEE_HOME`.
For a persistent deployment, translate the command into the host's service
manager and keep all installation paths, driver selection, state ownership,
and host identity in local deployment configuration rather than this reusable
integration.

The ingestor correlates the container ID embedded in `thread.cgroups` to the
authoritative local `tclone-runs.jsonl`. This registry records distinct run
identities and roles for sources and forks without relying on container labels
that Podman clones could inherit from their source.

## Operational notes

- Pin the Falco and driver versions appropriate for the deployment.
- Keep Falco stderr separate from its JSON stdout before piping to Gensee.
- Use bounded journald or file retention. The selected rules avoid the much
  higher overhead and storage cost of recording every syscall.
- Validate the rules with the exact Falco release before deployment; field and
  event support is versioned by Falco.
- Treat the supplied paths and host identifier as examples and configure them
  for the local installation.
