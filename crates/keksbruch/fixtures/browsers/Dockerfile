# The keksbruch browser-sidecar image: three pinned engines and their
# WebDrivers, baked with network ON so the harness can run the sidecar under
# `docker run --network=none` (loopback only) like every other column.
# Built by matrix.yml (buildx, gha cache) and tagged keksbruch-browsers:local.
#
# Version bumps are ARG edits here — reviewable, and the matrix footer shows
# the versions the run really used (the sidecar's selfcheck reports them).
FROM debian:trixie-slim

# Microsoft ships the deb with packaging revision -1; the driver zip has none.
ARG EDGE_VERSION=149.0.4022.98
# Chrome for Testing: versioned artifacts purpose-built for pinning (the brand
# Chrome deb channel serves only "latest"), with an exactly matching driver.
ARG CHROME_VERSION=149.0.7827.155
# Mozilla's release tarball — never the snap, which cannot run from a driver.
ARG FIREFOX_VERSION=152.0.3
ARG GECKODRIVER_VERSION=0.37.0

# Fetch tooling plus the sidecar's runtime: python3 (the driver), openssl (the
# throwaway TLS cert), fonts so rendering never stalls on an empty fontconfig,
# and Firefox's few libraries that Edge's dependency closure does not carry.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip xz-utils python3 openssl fonts-liberation \
        libgtk-3-0t64 libdbus-glib-1-2 libxt6 libasound2t64 libx11-xcb1 \
    && rm -rf /var/lib/apt/lists/*

# Edge first: apt resolves the full Chromium-runtime library closure from its
# Depends, which Chrome for Testing and the Firefox tarball then largely reuse.
RUN curl -fsSL -o /tmp/edge.deb \
        "https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-stable/microsoft-edge-stable_${EDGE_VERSION}-1_amd64.deb" \
    && apt-get update \
    && apt-get install -y --no-install-recommends /tmp/edge.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/edge.deb \
    && curl -fsSL -o /tmp/edgedriver.zip \
        "https://msedgedriver.microsoft.com/${EDGE_VERSION}/edgedriver_linux64.zip" \
    && unzip -q /tmp/edgedriver.zip -d /tmp/edgedriver \
    && install -m 0755 /tmp/edgedriver/msedgedriver /usr/local/bin/msedgedriver \
    && rm -r /tmp/edgedriver /tmp/edgedriver.zip

RUN curl -fsSL -o /tmp/chrome.zip \
        "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chrome-linux64.zip" \
    && curl -fsSL -o /tmp/chromedriver.zip \
        "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chromedriver-linux64.zip" \
    && unzip -q /tmp/chrome.zip -d /opt \
    && unzip -q /tmp/chromedriver.zip -d /opt \
    && ln -s /opt/chrome-linux64/chrome /usr/local/bin/chrome \
    && ln -s /opt/chromedriver-linux64/chromedriver /usr/local/bin/chromedriver \
    && rm /tmp/chrome.zip /tmp/chromedriver.zip

RUN curl -fsSL "https://archive.mozilla.org/pub/firefox/releases/${FIREFOX_VERSION}/linux-x86_64/en-US/firefox-${FIREFOX_VERSION}.tar.xz" \
        | tar -xJ -C /opt \
    && ln -s /opt/firefox/firefox /usr/local/bin/firefox \
    && curl -fsSL "https://github.com/mozilla/geckodriver/releases/download/v${GECKODRIVER_VERSION}/geckodriver-v${GECKODRIVER_VERSION}-linux64.tar.gz" \
        | tar -xz -C /usr/local/bin geckodriver
