# Third-party notices

This project is released under the MIT licence (see [LICENSE](LICENSE)).
It also contains, or redistributes, work by other projects. Those notices are
reproduced here in full, as their licences require.

## metatwin

`metatwin/` is a Python port of [metatwin](https://github.com/threatexpress/metatwin)
(`metatwin.ps1`) by Threat Express. The port follows the original's pipeline,
steps and purpose, so it is a derivative work and carries the original licence:

```text
MIT License

Copyright (c) 2024 Threat Express

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## SigThief

`sigthief/` is the upstream [SigThief](https://github.com/secretsquirrel/SigThief)
repository, included as a git submodule. It is redistributed as source (the
submodule), inside the Docker image, and as `dist/SigThief.exe`, so its licence
travels with those artefacts:

```text
BSD 3-Clause License

Copyright (c) 2017, Josh Pitts
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Resource Hacker

`resourcehacker/` reimplements the command-line behaviour of
[Resource Hacker](https://www.angusj.com/resourcehacker/) by Angus Johnson.
Resource Hacker is proprietary freeware: it is not open source, no source code
was copied, and no Resource Hacker code is distributed here. The name and the
observable CLI behaviour (switches, mask grammar, log format) are credited for
compatibility only, which is why no licence notice appears above.

## pe_tools

[pe_tools](https://github.com/avast/pe_tools) is a runtime dependency, not
vendored here. Its own distribution carries its licence.
