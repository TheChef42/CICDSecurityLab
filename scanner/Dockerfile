FROM node:20-bookworm

ARG GITLEAKS_VERSION=8.24.3

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/checkov/bin:/opt/semgrep/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      python3 \
      python3-pip \
      python3-venv \
      tar \
      unzip \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/checkov \
    && /opt/checkov/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/checkov/bin/pip install --no-cache-dir checkov \
    && python3 -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/semgrep/bin/pip install --no-cache-dir semgrep

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://get.anchore.io/grype \
      | sh -s -- -b /usr/local/bin \
    && curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks \
    && npm install -g snyk

WORKDIR /workspace

CMD ["bash", "/workspace/scanner/run-all.sh"]
