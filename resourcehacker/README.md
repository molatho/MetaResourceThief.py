# Resource Hacker, reimplemented

The `ResourceHacker` executable, plus the PE library the `metatwin` subproject
imports. See the repository [README](../README.md) for the whole picture.

```console
$ ResourceHacker -open source.exe -action extract -mask ,,, -save out.res -log out.log
$ ResourceHacker -open target.exe -save new.exe -resource out.res -action replace
```

Actions: `extract`, `addoverwrite`, `replace`.

Install from this directory:

```console
pip install -e .[dev]
```

## Library modules

The package doubles as the shared PE toolkit for `metatwin`:

| Module | Contents |
|---|---|
| `resfile.py` | `.res` reader/writer |
| `pelayer.py` | PE resource tree, merge modes, icon renumbering |
| `mask.py` | the `-mask` grammar |
| `logfile.py` | the UTF-16LE log |
