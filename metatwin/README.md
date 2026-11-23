# metatwin

Clones a source binary's resources, signature and timestamps onto a target.

```console
$ metatwin -s source.exe -t payload.exe -o outdir --sign
```

Steps: extract the source's resources, install them into the target with
`replace` semantics (nothing of the target's resources survives), copy the
source's Authenticode certificate table with SigThief, timestomp the output to
the source's timestamps, and print the resulting version info.

Runs on Linux and Windows; needs neither PowerShell nor a compiled
`sigthief.exe`. The signature step is upstream SigThief, so `--sign` needs the
`sigthief` submodule (`git submodule update --init`) or an explicit
`--sigthief path/to/sigthief.py` (`$SIGTHIEF` works too). Without `--sign` the
submodule is not needed.

Depends on the `resourcehacker` distribution. Install both from the repository
root.

`metatwin/` is a port of [metatwin](https://github.com/threatexpress/metatwin)
by Threat Express and carries its MIT licence; the notice is in
[`metatwin/NOTICE`](metatwin/NOTICE) and in the repository's
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
