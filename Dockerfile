# Three local tools plus upstream SigThief from the git submodule, in one image.
# ResourceHacker is the default entry point; `--entrypoint SigThief`,
# `--entrypoint metatwin` or `--entrypoint MetaResourceThief` switches tools.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY resourcehacker ./resourcehacker
COPY metatwin ./metatwin
COPY metaresourcethief ./metaresourcethief
COPY packaging ./packaging
COPY THIRD_PARTY_NOTICES.md /app/NOTICES/
COPY packaging/sigthief/LICENSE /app/NOTICES/SigThief-LICENSE

RUN pip install --no-cache-dir \
        ./packaging ./resourcehacker ./metatwin ./metaresourcethief \
    && printf '#!/bin/sh\nexec python /app/packaging/sigthief/sigthief.py "$@"\n' > /usr/local/bin/SigThief \
    && chmod +x /usr/local/bin/SigThief \
    && useradd --create-home --shell /usr/sbin/nologin runner

USER runner
WORKDIR /work

ENTRYPOINT ["ResourceHacker"]
CMD ["-help"]
