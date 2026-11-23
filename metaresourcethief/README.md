# MetaResourceThief

One command that copies a PE's resources, its Authenticode signature, or both.

```console
$ MetaResourceThief -s source.exe -t target.exe -o out.exe --sign
[*] copied 207 resources from source.exe -> out.exe
[*] copied signature (77680 bytes) from source.exe -> out.exe
[+] output: out.exe
```

`-s/--source` is the binary to copy from, `-t/--target` the binary to copy onto,
`-o/--output` the file to write. The two copies are independent:

| Command | Result |
|---|---|
| `-s src -t tgt -o out --sign` | resources + signature |
| `-s src -t tgt -o out` | resources only |
| `-s src -t tgt -o out --sign --no-metadata` | signature only |

Resources are installed with `replace` semantics — nothing of the target's own
resource tree survives, matching [`metatwin`](../metatwin/README.md). The
signature is copied by upstream [SigThief](../packaging/sigthief/sigthief.py),
the same way `metatwin --sign` does it.

Neither timestomping nor version-info printing is done here; use `metatwin` for
the full clone. `--output` must differ from `--source` and `--target`, and
`--no-metadata` without `--sign` is an error rather than a no-op.

Depends on the `resourcehacker` and `metatwin` distributions; install the
repository's `packaging` project too (it supplies the `sigthief` module).