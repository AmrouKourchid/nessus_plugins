#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5833. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(213102);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2024-11614");

  script_name(english:"Debian dsa-5833 : dpdk - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5833
advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5833-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    December 17, 2024                     https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : dpdk
    CVE ID         : CVE-2024-11614

    A buffer overflow was discovered in the vhost code of DPDK, a set of
    libraries for fast packet processing, which could result in denial of
    service or the execution of arbitrary code by malicious
    guests/containers.

    For the stable distribution (bookworm), this problem has been fixed in
    version 22.11.7-1~deb12u1.

    We recommend that you upgrade your dpdk packages.

    For the detailed security status of dpdk please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/dpdk

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/dpdk");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-11614");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/dpdk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the dpdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11614");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-acl23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-baseband-acc23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-baseband-fpga-5gnr-fec23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-baseband-fpga-lte-fec23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-baseband-la12xx23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-baseband-null23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-baseband-turbo-sw23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bbdev23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bitratestats23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bpf23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-auxiliary23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-dpaa23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-fslmc23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-ifpga23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-pci23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-vdev23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-vmbus23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-cfgfile23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-cmdline23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-cnxk23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-cpt23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-dpaax23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-iavf23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-idpf23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-mlx5-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-octeontx23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-qat23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-sfc-efx23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-compress-isal23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-compress-mlx5-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-compress-octeontx23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-compress-zlib23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-compressdev23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-bcmfs23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-caam-jr23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-ccp23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-cnxk23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-dpaa-sec23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-dpaa2-sec23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-ipsec-mb23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-mlx5-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-nitrox23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-null23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-octeontx23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-openssl23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-scheduler23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-virtio23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-cryptodev23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-distributor23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-dma-cnxk23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-dma-dpaa2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-dma-dpaa23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-dma-hisilicon23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-dma-idxd23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-dma-ioat23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-dma-skeleton23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-dmadev23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-eal23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-efd23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-ethdev23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-cnxk23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-dlb2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-dpaa2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-dpaa23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-dsw23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-octeontx23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-opdl23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-skeleton23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-sw23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-eventdev23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-fib23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-gpudev23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-graph23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-gro23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-gso23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-hash23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-ip-frag23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-ipsec23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-jobstats23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-kvargs23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-latencystats23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-lpm23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mbuf23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-member23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-bucket23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-cnxk23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-dpaa2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-dpaa23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-octeontx23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-ring23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-stack23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-allpmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-baseband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-bus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-compress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-dma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-mempool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-raw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meter23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-metrics23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-af-packet23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-af-xdp23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ark23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-atlantic23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-avp23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-axgbe23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-bnx2x23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-bnxt23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-bond23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-cnxk23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-cxgbe23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-dpaa2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-dpaa23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-e1000-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ena23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-enetc23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-enetfec23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-enic23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-failsafe23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-fm10k23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-gve23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-hinic23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-hns3-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-i40e23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-iavf23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ice23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-idpf23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-igc23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ionic23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ipn3ke23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ixgbe23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-liquidio23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-memif23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-mlx4-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-mlx5-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-netvsc23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-nfp23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ngbe23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-null23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-octeon-ep23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-octeontx23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-pcap23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-pfe23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-qede23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ring23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-sfc23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-softnic23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-tap23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-thunderx23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-txgbe23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-vdev-netvsc23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-vhost23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-virtio23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-vmxnet3-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-node23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pcapng23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pci23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pdump23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pipeline23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-port23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-power23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-cnxk-bphy23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-cnxk-gpio23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-dpaa2-cmdif23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-ifpga23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-ntb23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-skeleton23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-rawdev23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-rcu23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-regex-cn9k23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-regex-mlx5-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-regexdev23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-reorder23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-rib23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-ring23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-sched23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-security23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-stack23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-table23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-telemetry23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-timer23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-vdpa-ifc23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-vdpa-mlx5-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-vdpa-sfc23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-vhost23");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'dpdk', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'dpdk-dev', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'dpdk-doc', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libdpdk-dev', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-acl23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-baseband-acc23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-baseband-fpga-5gnr-fec23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-baseband-fpga-lte-fec23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-baseband-la12xx23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-baseband-null23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-baseband-turbo-sw23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-bbdev23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-bitratestats23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-bpf23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-bus-auxiliary23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-bus-dpaa23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-bus-fslmc23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-bus-ifpga23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-bus-pci23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-bus-vdev23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-bus-vmbus23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-cfgfile23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-cmdline23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-common-cnxk23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-common-cpt23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-common-dpaax23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-common-iavf23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-common-idpf23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-common-mlx5-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-common-octeontx23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-common-qat23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-common-sfc-efx23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-compress-isal23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-compress-mlx5-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-compress-octeontx23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-compress-zlib23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-compressdev23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-bcmfs23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-caam-jr23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-ccp23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-cnxk23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-dpaa-sec23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-dpaa2-sec23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-ipsec-mb23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-mlx5-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-nitrox23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-null23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-octeontx23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-openssl23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-scheduler23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-crypto-virtio23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-cryptodev23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-distributor23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-dma-cnxk23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-dma-dpaa2-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-dma-dpaa23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-dma-hisilicon23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-dma-idxd23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-dma-ioat23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-dma-skeleton23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-dmadev23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-eal23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-efd23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-ethdev23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-event-cnxk23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-event-dlb2-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-event-dpaa2-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-event-dpaa23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-event-dsw23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-event-octeontx23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-event-opdl23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-event-skeleton23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-event-sw23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-eventdev23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-fib23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-gpudev23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-graph23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-gro23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-gso23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-hash23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-ip-frag23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-ipsec23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-jobstats23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-kvargs23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-latencystats23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-lpm23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-mbuf23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-member23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-mempool-bucket23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-mempool-cnxk23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-mempool-dpaa2-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-mempool-dpaa23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-mempool-octeontx23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-mempool-ring23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-mempool-stack23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-mempool23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meta-all', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meta-allpmds', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meta-baseband', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meta-bus', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meta-common', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meta-compress', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meta-crypto', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meta-dma', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meta-event', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meta-mempool', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meta-net', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meta-raw', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-meter23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-metrics23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-af-packet23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-af-xdp23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-ark23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-atlantic23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-avp23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-axgbe23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-bnx2x23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-bnxt23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-bond23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-cnxk23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-cxgbe23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-dpaa2-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-dpaa23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-e1000-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-ena23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-enetc23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-enetfec23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-enic23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-failsafe23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-fm10k23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-gve23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-hinic23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-hns3-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-i40e23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-iavf23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-ice23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-idpf23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-igc23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-ionic23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-ipn3ke23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-ixgbe23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-liquidio23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-memif23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-mlx4-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-mlx5-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-netvsc23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-nfp23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-ngbe23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-null23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-octeon-ep23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-octeontx23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-pcap23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-pfe23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-qede23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-ring23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-sfc23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-softnic23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-tap23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-thunderx23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-txgbe23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-vdev-netvsc23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-vhost23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-virtio23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net-vmxnet3-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-net23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-node23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-pcapng23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-pci23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-pdump23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-pipeline23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-port23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-power23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-raw-cnxk-bphy23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-raw-cnxk-gpio23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-raw-dpaa2-cmdif23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-raw-ifpga23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-raw-ntb23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-raw-skeleton23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-rawdev23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-rcu23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-regex-cn9k23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-regex-mlx5-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-regexdev23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-reorder23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-rib23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-ring23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-sched23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-security23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-stack23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-table23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-telemetry23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-timer23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-vdpa-ifc23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-vdpa-mlx5-23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-vdpa-sfc23', 'reference': '22.11.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librte-vhost23', 'reference': '22.11.7-1~deb12u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dpdk / dpdk-dev / dpdk-doc / libdpdk-dev / librte-acl23 / etc');
}
