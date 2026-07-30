FROM python:3.11.13-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /build

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir "build>=1.3,<2.0" \
    && python -m build --wheel --outdir /wheelhouse

FROM python:3.11.13-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="AegisHunt" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.description="Local autonomous threat-hunting research prototype"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MPLCONFIGDIR=/tmp/matplotlib \
    AEGISHUNT_CONFIG=/opt/aegishunt/configs/docker.yaml

RUN groupadd --gid 10001 aegishunt \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin aegishunt

WORKDIR /opt/aegishunt
COPY --from=builder /wheelhouse/*.whl /tmp/
RUN python -m pip install --no-cache-dir /tmp/*.whl \
    && rm -f /tmp/*.whl

COPY --chown=root:root pyproject.toml README.md ./
COPY --chown=root:root configs ./configs
COPY --chown=root:root data/sample ./data/sample
RUN mkdir -p runtime/data runtime/artifacts runtime/reports \
    && ln -s runtime/artifacts artifacts \
    && ln -s runtime/reports reports \
    && chown -R aegishunt:aegishunt runtime

USER 10001:10001
EXPOSE 8000 8501
ENTRYPOINT ["aegishunt"]
CMD ["doctor"]
