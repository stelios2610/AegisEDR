FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV UBUNTU_VERSION=24.04.2
ENV UBUNTU_ISO=ubuntu-24.04.2-live-server-amd64.iso

RUN apt-get update && apt-get install -y \
    xorriso squashfs-tools p7zip-full wget curl \
    rsync python3 python3-pip ca-certificates \
    isolinux syslinux-utils genisoimage \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . /aegisedr

# Download Ubuntu ISO at build time (cached in layer)
RUN wget -q --show-progress \
    "https://releases.ubuntu.com/${UBUNTU_VERSION}/${UBUNTU_ISO}" \
    -O /build/${UBUNTU_ISO} || echo "Will download at runtime"

RUN chmod +x /aegisedr/build/build_iso_inner.sh

CMD ["/bin/bash", "/aegisedr/build/build_iso_inner.sh"]
