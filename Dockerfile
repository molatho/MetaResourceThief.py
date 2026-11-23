# Two local tools plus upstream SigThief from the git submodule, in one image.
# ResourceHacker is the default entry point; `--entrypoint SigThief` or
# `--entrypoint metatwin` switches tools.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY resourcehacker ./resourcehacker
COPY metatwin ./metatwin
COPY sigthief ./sigthief
COPY THIRD_PARTY_NOTICES.md /app/NOTICES/
COPY sigthief/LICENSE /app/NOTICES/SigThief-LICENSE

RUN pip install --no-cache-dir ./resourcehacker ./metatwin \
    && printf '#!/bin/sh\nexec python /app/sigthief/sigthief.py "$@"\n' > /usr/local/bin/SigThief \
    && chmod +x /usr/local/bin/SigThief \
    && useradd --create-home --shell /usr/sbin/nologin runner

# metatwin --sign runs this script; point it at the copy inside the image.
ENV SIGTHIEF=/app/sigthief/sigthief.py

USER runner
WORKDIR /work

ENTRYPOINT ["ResourceHacker"]
CMD ["-help"]
