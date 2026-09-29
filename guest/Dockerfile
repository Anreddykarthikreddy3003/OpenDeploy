# syntax=docker/dockerfile:1
# OpenDeploy managed Linux guest (PRD §3.3): the data plane for Windows
# (WSL2 distribution) and macOS (Virtualization.framework VM). It is a plain
# Debian system with systemd, containerd, rootless BuildKit, gVisor and
# Caddy, plus the same opendeploy package a Linux server installs; the first
# boot runs the package installer. Third-party binaries are pinned by digest.
#
# Built by guest/build.sh; GUEST_KIND selects wsl2 or vz specifics.
ARG DEBIAN_IMAGE=debian:trixie-slim
FROM ${DEBIAN_IMAGE}
ARG TARGETARCH
ARG GUEST_KIND=wsl2
ARG CADDY_VERSION=2.10.2
ARG BUILDKIT_VERSION=0.23.2
ARG ROOTLESSKIT_VERSION=2.3.5
ARG GVISOR_RELEASE=20250922.0
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends \
      systemd systemd-sysv dbus ca-certificates curl nftables iproute2 iputils-ping \
      uidmap slirp4netns containerd runc e2fsprogs kmod procps less \
 && if [ "$GUEST_KIND" = vz ]; then \
      apt-get install -y -q --no-install-recommends systemd-resolved initramfs-tools zstd; \
    fi \
 && rm -rf /var/lib/apt/lists/*

# Pinned third-party binaries (sha256 of the release archives; gVisor sha512).
# An enterprise TLS-inspection CA can be supplied as the build secret
# "build-ca" (guest/build.sh: OPENDEPLOY_BUILD_CA_BUNDLE); it is used for
# the downloads only and never stored in the image.
RUN --mount=type=secret,id=build-ca,required=false \
    case "$TARGETARCH" in \
      amd64) caddy=5c218bc34c9197369263da7e9317a83acdbd80ef45d94dca5eff76e727c67cdd; \
             bk=2771c3403e3a1f75a83cde387a05365794d3b900c355e864772a36c3ce541f82; \
             rk=118208e25becd144ee7317c172fc9decce7b16174d5c1bbf80f1d1d0eacc6b5f; rkarch=x86_64; \
             runsc=aa008e497d50cc97eb3103645a80ede5f40f13b0d55c675ef3774ecc60cac299e3941253daf9fcbbd097294d7826a2dcf2343eec39a6b52646ec9deaceb3c9cc; \
             shim=e5478ab26ed5e20a503661ccf23b39a45a2ef593e5ad2d8db36c4d44917747efdc22f6af8e76e0c0eeec91e28cc8efedd9c0ed640cde7c9d1843293d47b19196 ;; \
      arm64) caddy=501e955fa634c5aab63247458c3ac655cfdd6cbf1e0436528f41248451c190ac; \
             bk=6385ff70b2fb4134b50ac3183eea3a0b06c6f6129173940d73178ae0477368f1; \
             rk=478c14c3195bf989cd9a8e6bd129d227d5d88f1c11418967ffdc84a0072cc7a2; rkarch=aarch64; \
             runsc=a31a71a24d20e5800c76bf44a9cf33af0dec063c8657fac65805994eef6b136bc66bf4780a4c8acfe0c9d87733c30432b1e4c31cf9994a23d448c8af0865dcd7; \
             shim=038c3a7180520538d488d6dead7c04555d82060d301e3d785b4b6315a33e51b20b7895caa8dedfcf8cfeb0f355ea7aea579c2ea34ea46c5aad408cc962dd282f ;; \
      *) echo "unsupported arch $TARGETARCH"; exit 1 ;; \
    esac; \
    cd /tmp; \
    ca=(); [ -s /run/secrets/build-ca ] && ca=(--cacert /run/secrets/build-ca); \
    fetch() { curl -fsSL --retry 4 "${ca[@]}" -o "$1" "$2"; }; \
    fetch caddy.tgz "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    echo "$caddy  caddy.tgz" | sha256sum -c -; tar -xzf caddy.tgz -C /usr/bin caddy; \
    fetch bk.tgz "https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-${TARGETARCH}.tar.gz"; \
    echo "$bk  bk.tgz" | sha256sum -c -; tar -xzf bk.tgz -C /usr bin/buildkitd bin/buildctl bin/buildkit-runc; \
    fetch rk.tgz "https://github.com/rootless-containers/rootlesskit/releases/download/v${ROOTLESSKIT_VERSION}/rootlesskit-${rkarch}.tar.gz"; \
    echo "$rk  rk.tgz" | sha256sum -c -; tar -xzf rk.tgz -C /usr/bin rootlesskit rootlessctl; \
    g="https://storage.googleapis.com/gvisor/releases/release/${GVISOR_RELEASE}/${rkarch}"; \
    fetch runsc "$g/runsc"; echo "$runsc  runsc" | sha512sum -c -; \
    fetch shim "$g/containerd-shim-runsc-v1"; echo "$shim  shim" | sha512sum -c -; \
    install -m 0755 runsc /usr/bin/runsc; install -m 0755 shim /usr/bin/containerd-shim-runsc-v1; \
    rm -f /tmp/*.tgz /tmp/runsc /tmp/shim

# Guest configuration (common, then kind-specific).
COPY rootfs/common/ /
COPY rootfs/${GUEST_KIND}/ /
RUN echo "$GUEST_KIND" > /usr/lib/opendeploy-guest-kind

# The node package: identical to the Linux server install. Its postinst
# skips the installer without a running systemd; first boot runs it.
COPY opendeploy.deb /tmp/opendeploy.deb
RUN apt-get update -q && apt-get install -y -q --no-install-recommends /tmp/opendeploy.deb \
 && rm -rf /var/lib/apt/lists/* /tmp/opendeploy.deb

# VM only: a kernel and initramfs; modules are shipped as a separate image
# so kernel and modules always come from the same host package.
RUN if [ "$GUEST_KIND" = vz ]; then \
      chmod +x /etc/initramfs-tools/scripts/local-bottom/opendeploy-modules; \
      case "$TARGETARCH" in amd64) k=linux-image-cloud-amd64 ;; arm64) k=linux-image-arm64 ;; esac; \
      apt-get update -q && apt-get install -y -q --no-install-recommends "$k" && rm -rf /var/lib/apt/lists/*; \
      systemctl enable systemd-networkd systemd-resolved opendeploy-guest-agent.service; \
    fi

RUN systemctl enable opendeploy-guest-setup.service \
 && systemctl mask systemd-firstboot.service getty@tty1.service \
 && passwd -l root \
 && echo opendeploy > /etc/hostname \
 && apt-get clean && rm -rf /var/cache/apt/* /var/log/*.log /tmp/*
