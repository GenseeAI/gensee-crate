# Falco Linux system-event bridge

Gensee's Falco bridge captures a deliberately bounded kernel-event stream for
trajectory reconstruction while keeping enforcement and collection separate.
Falco observes selected process, file, network, and high-risk syscall events;
`gensee ingest falco` redacts and normalizes its JSON output into
`SystemEvent` records. Gensee extracts the Podman container id from Falco's
built-in cgroup field and matches it to the local Tclone registry, attaching
the event to that source or fork run. This avoids a dependency on Falco's
optional container metadata plugin.

This is a capture layer, not a claim that Tclone is a confinement boundary.
The Machine A rule pack records:

- process execution inside containers;
- opens under `/workspace` plus file mutation syscalls;
- connect, accept, bind, and listen activity;
- tracing, BPF, module, mount, namespace, and identity-changing syscalls.

It intentionally does not record read/write payload buffers, environment
variables, or every syscall. Command lines and Falco fields pass through the
same secret-redaction floor as other Gensee system-event sources.

## Machine A

Machine A's custom Tclone kernel currently needs Falco's kernel-module engine.
Load a Falco driver built for the exact running kernel, then install and enable
`gensee-falco-machine-a.service`. The config uses Falco's durable program output
to feed JSON directly into Gensee with
`GENSEE_HOME=/home/yiying_gensee_ai/.gensee`, so records share the operator's
timeline and Tclone registry. For an ad-hoc foreground check, run:

```bash
sudo falco \
  -c integrations/falco/falco-machine-a.yaml \
  -r integrations/falco/gensee-machine-a-rules.yaml \
  | sudo env GENSEE_HOME=/home/yiying_gensee_ai/.gensee \
      gensee ingest falco --host machine-a-sandbox
```

The ingestor correlates the container id embedded in `thread.cgroups` to the
authoritative local `tclone-runs.jsonl`. This registry records the distinct run
identity and role for sources and forks without relying on container labels
that Podman clones would inherit from their source.

## Machine B

Machine B deliberately uses ordinary network and application logging rather
than installing Gensee: `gensee-network-trace-machine-b.service` adds a bounded
128 MiB pcap ring with a 96-byte snap length, enough for link/IP/TCP metadata
but not HTTP payloads or authorization headers. Correlate it with Artifactory
request logs and VPC Flow/Firewall Logs for the exact A -> B -> canary route.

## Operational notes

- Pin the Falco and driver versions and use the same rule/config revision in
  baseline and enforcement runs.
- Keep Falco stderr separate from its JSON stdout before piping to Gensee.
- Use bounded journald/file retention. The selected rule set avoids the much
  higher overhead and storage cost of recording every syscall.
- Validate rules with the exact Falco release before deployment; field and
  event support is versioned by Falco.
- The supplied units are intentionally lab-specific (VM names, addresses, and
  the OS Login home path); parameterize those values before reuse elsewhere.
