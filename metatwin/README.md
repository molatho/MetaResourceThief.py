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
`sigthief.exe`. The signature step imports the `sigthief` distribution, built
from the repository's `packaging/` project.

Depends on the `resourcehacker` and `sigthief` distributions. Install them from
the repository root, together with `packaging`:

```console
$ git submodule update --init --recursive
$ pip install ./packaging -e ./resourcehacker -e ./metatwin
```

`metatwin/` is a port of [metatwin](https://github.com/threatexpress/metatwin)
by Threat Express and carries its MIT licence; the notice is in
[`metatwin/NOTICE`](metatwin/NOTICE) and in the repository's
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
