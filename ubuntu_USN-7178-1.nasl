#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7178-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213261);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2024-11614");
  script_xref(name:"USN", value:"7178-1");

  script_name(english:"Ubuntu 22.04 LTS / 24.04 LTS / 24.10 : DPDK vulnerability (USN-7178-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by a vulnerability as
referenced in the USN-7178-1 advisory.

    It was discovered that DPDK incorrectly handled the Vhost library checksum offload feature. An malicious
    guest could possibly use this issue to cause the hypervisor's vSwitch to crash, resulting in a denial of
    service.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7178-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11614");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-acl22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-acl24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-acc100-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-acc24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-fpga-5gnr-fec22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-fpga-5gnr-fec24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-fpga-lte-fec22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-fpga-lte-fec24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-la12xx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-la12xx24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-null22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-null24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-turbo-sw22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-turbo-sw24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bbdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bbdev24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bitratestats22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bitratestats24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bpf22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bpf24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-auxiliary22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-auxiliary24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-cdx24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-dpaa22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-dpaa24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-fslmc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-fslmc24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-ifpga22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-ifpga24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-pci22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-pci24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-platform24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-vdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-vdev24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-vmbus22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-vmbus24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cfgfile22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cfgfile24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cmdline22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cmdline24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-cnxk22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-cnxk24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-cpt22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-cpt24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-dpaax22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-dpaax24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-iavf22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-iavf24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-idpf24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-mlx5-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-mlx5-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-nfp24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-octeontx2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-octeontx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-octeontx24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-qat22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-qat24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-sfc-efx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-sfc-efx24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compress-isal22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compress-isal24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compress-mlx5-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compress-mlx5-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compress-octeontx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compress-octeontx24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compress-zlib22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compress-zlib24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compressdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compressdev24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-bcmfs22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-bcmfs24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-caam-jr22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-caam-jr24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-ccp22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-ccp24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-cnxk22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-cnxk24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-dpaa-sec22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-dpaa-sec24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-dpaa2-sec22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-dpaa2-sec24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-ipsec-mb22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-ipsec-mb24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-mlx5-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-mlx5-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-nitrox22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-nitrox24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-null22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-null24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-octeontx2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-octeontx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-octeontx24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-openssl22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-openssl24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-scheduler22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-scheduler24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-virtio22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-virtio24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cryptodev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cryptodev24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dispatcher24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-distributor22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-distributor24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-cnxk22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-cnxk24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-dpaa2-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-dpaa22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-dpaa24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-hisilicon22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-hisilicon24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-idxd22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-idxd24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-ioat22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-ioat24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-skeleton22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-skeleton24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dmadev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dmadev24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eal22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eal24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-efd22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-efd24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ethdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ethdev24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-cnxk22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-cnxk24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-dlb2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-dlb2-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-dpaa2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-dpaa2-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-dpaa22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-dpaa24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-dsw22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-dsw24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-octeontx2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-octeontx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-octeontx24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-opdl22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-opdl24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-skeleton22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-skeleton24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-sw22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-sw24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eventdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eventdev24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-fib22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-fib24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-flow-classify22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gpudev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gpudev24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-graph22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-graph24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gro22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gro24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gso22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gso24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-hash22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-hash24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ip-frag22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ip-frag24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ipsec22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ipsec24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-jobstats22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-jobstats24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kni22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kvargs22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kvargs24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-latencystats22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-latencystats24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-log24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-lpm22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-lpm24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mbuf22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mbuf24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-member22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-member24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-bucket22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-bucket24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-cnxk22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-cnxk24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-dpaa2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-dpaa2-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-dpaa22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-dpaa24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-octeontx2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-octeontx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-octeontx24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-ring22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-ring24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-stack22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-stack24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-allpmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-baseband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-bus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-compress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-dma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-mempool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-raw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meter22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meter24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-metrics22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-metrics24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ml-cnxk24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mldev24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-af-packet22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-af-packet24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-af-xdp22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-af-xdp24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ark22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ark24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-atlantic22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-atlantic24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-avp22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-avp24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-axgbe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-axgbe24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-bnx2x22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-bnx2x24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-bnxt22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-bnxt24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-bond22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-bond24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-cnxk22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-cnxk24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-cpfl24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-cxgbe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-cxgbe24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-dpaa2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-dpaa2-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-dpaa22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-dpaa24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-e1000-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-e1000-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ena22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ena24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-enetc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-enetc24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-enetfec22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-enetfec24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-enic22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-enic24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-failsafe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-failsafe24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-fm10k22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-fm10k24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-gve24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-hinic22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-hinic24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-hns3-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-hns3-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-i40e22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-i40e24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-iavf22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-iavf24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ice22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ice24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-idpf24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-igc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-igc24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ionic22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ionic24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ipn3ke22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ipn3ke24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ixgbe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ixgbe24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-kni22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-liquidio22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-mana24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-memif22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-memif24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-mlx4-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-mlx4-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-mlx5-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-mlx5-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-netvsc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-netvsc24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-nfp22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-nfp24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ngbe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ngbe24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-null22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-null24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-octeon-ep24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-octeontx-ep22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-octeontx2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-octeontx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-octeontx24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-pcap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-pcap24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-pfe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-pfe24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-qede22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-qede24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ring22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ring24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-sfc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-sfc24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-softnic22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-softnic24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-tap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-tap24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-thunderx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-thunderx24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-txgbe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-txgbe24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-vdev-netvsc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-vdev-netvsc24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-vhost22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-vhost24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-virtio22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-virtio24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-vmxnet3-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-vmxnet3-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-node22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-node24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pcapng22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pcapng24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pci22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pci24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pdcp24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pdump22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pdump24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pipeline22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pipeline24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-port22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-port24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-power22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-power24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-cnxk-bphy22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-cnxk-bphy24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-cnxk-gpio24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-dpaa2-cmdif22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-dpaa2-cmdif24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-dpaa2-qdma22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-ifpga22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-ifpga24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-ntb22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-ntb24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-skeleton22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-skeleton24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rcu22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rcu24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-regex-cn9k24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-regex-mlx5-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-regex-mlx5-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-regex-octeontx2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-regexdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-regexdev24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-reorder22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-reorder24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rib22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rib24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ring22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ring24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-sched22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-sched24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-security22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-security24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-stack22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-stack24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-table22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-table24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-telemetry22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-telemetry24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-timer22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-timer24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vdpa-ifc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vdpa-ifc24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vdpa-mlx5-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vdpa-mlx5-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vdpa-nfp24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vdpa-sfc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vdpa-sfc24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vhost22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vhost24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'dpdk', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'dpdk-dev', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'libdpdk-dev', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-acl22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-baseband-acc100-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-baseband-fpga-5gnr-fec22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-baseband-fpga-lte-fec22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-baseband-la12xx22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-baseband-null22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-baseband-turbo-sw22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-bbdev22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-bitratestats22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-bpf22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-bus-auxiliary22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-bus-dpaa22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-bus-fslmc22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-bus-ifpga22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-bus-pci22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-bus-vdev22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-bus-vmbus22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-cfgfile22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-cmdline22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-common-cnxk22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-common-cpt22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-common-dpaax22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-common-iavf22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-common-mlx5-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-common-octeontx2-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-common-octeontx22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-common-qat22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-common-sfc-efx22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-compress-isal22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-compress-mlx5-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-compress-octeontx22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-compress-zlib22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-compressdev22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-bcmfs22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-caam-jr22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-ccp22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-cnxk22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-dpaa-sec22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-dpaa2-sec22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-ipsec-mb22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-mlx5-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-nitrox22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-null22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-octeontx2-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-octeontx22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-openssl22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-scheduler22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-virtio22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-cryptodev22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-distributor22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-dma-cnxk22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-dma-dpaa22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-dma-hisilicon22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-dma-idxd22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-dma-ioat22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-dma-skeleton22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-dmadev22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-eal22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-efd22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-ethdev22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-event-cnxk22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-event-dlb2-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-event-dpaa2-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-event-dpaa22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-event-dsw22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-event-octeontx2-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-event-octeontx22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-event-opdl22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-event-skeleton22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-event-sw22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-eventdev22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-fib22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-flow-classify22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-gpudev22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-graph22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-gro22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-gso22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-hash22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-ip-frag22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-ipsec22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-jobstats22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-kni22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-kvargs22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-latencystats22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-lpm22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-mbuf22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-member22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-bucket22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-cnxk22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-dpaa2-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-dpaa22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-octeontx2-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-octeontx22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-ring22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-stack22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-mempool22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-meta-all', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-meta-allpmds', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-meta-baseband', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-meta-bus', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-meta-compress', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-meta-crypto', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-meta-dma', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-meta-event', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-meta-mempool', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-meta-net', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-meta-raw', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-meter22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-metrics22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-af-packet22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-af-xdp22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-ark22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-atlantic22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-avp22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-axgbe22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-bnx2x22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-bnxt22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-bond22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-cnxk22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-cxgbe22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-dpaa2-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-dpaa22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-e1000-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-ena22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-enetc22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-enetfec22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-enic22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-failsafe22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-fm10k22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-hinic22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-hns3-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-i40e22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-iavf22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-ice22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-igc22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-ionic22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-ipn3ke22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-ixgbe22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-kni22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-liquidio22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-memif22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-mlx4-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-mlx5-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-netvsc22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-nfp22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-ngbe22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-null22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-octeontx-ep22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-octeontx2-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-octeontx22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-pcap22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-pfe22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-qede22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-ring22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-sfc22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-softnic22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-tap22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-thunderx22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-txgbe22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-vdev-netvsc22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-vhost22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-virtio22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net-vmxnet3-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-net22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-node22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-pcapng22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-pci22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-pdump22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-pipeline22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-port22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-power22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-raw-cnxk-bphy22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-raw-dpaa2-cmdif22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-raw-dpaa2-qdma22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-raw-ifpga22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-raw-ntb22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-raw-skeleton22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-rawdev22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-rcu22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-regex-mlx5-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-regex-octeontx2-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-regexdev22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-reorder22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-rib22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-ring22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-sched22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-security22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-stack22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-table22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-telemetry22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-timer22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-vdpa-ifc22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-vdpa-mlx5-22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-vdpa-sfc22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'librte-vhost22', 'pkgver': '21.11.6-0ubuntu0.22.04.2'},
    {'osver': '24.04', 'pkgname': 'dpdk', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'dpdk-dev', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'libdpdk-dev', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-acl24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-baseband-acc24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-baseband-fpga-5gnr-fec24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-baseband-fpga-lte-fec24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-baseband-la12xx24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-baseband-null24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-baseband-turbo-sw24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-bbdev24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-bitratestats24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-bpf24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-bus-auxiliary24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-bus-cdx24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-bus-dpaa24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-bus-fslmc24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-bus-ifpga24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-bus-pci24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-bus-platform24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-bus-vdev24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-bus-vmbus24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-cfgfile24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-cmdline24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-common-cnxk24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-common-cpt24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-common-dpaax24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-common-iavf24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-common-idpf24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-common-mlx5-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-common-nfp24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-common-octeontx24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-common-qat24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-common-sfc-efx24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-compress-isal24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-compress-mlx5-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-compress-octeontx24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-compress-zlib24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-compressdev24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-bcmfs24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-caam-jr24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-ccp24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-cnxk24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-dpaa-sec24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-dpaa2-sec24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-ipsec-mb24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-mlx5-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-nitrox24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-null24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-octeontx24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-openssl24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-scheduler24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-crypto-virtio24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-cryptodev24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-dispatcher24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-distributor24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-dma-cnxk24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-dma-dpaa2-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-dma-dpaa24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-dma-hisilicon24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-dma-idxd24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-dma-ioat24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-dma-skeleton24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-dmadev24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-eal24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-efd24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-ethdev24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-event-cnxk24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-event-dlb2-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-event-dpaa2-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-event-dpaa24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-event-dsw24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-event-octeontx24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-event-opdl24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-event-skeleton24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-event-sw24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-eventdev24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-fib24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-gpudev24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-graph24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-gro24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-gso24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-hash24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-ip-frag24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-ipsec24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-jobstats24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-kvargs24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-latencystats24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-log24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-lpm24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-mbuf24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-member24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-mempool-bucket24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-mempool-cnxk24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-mempool-dpaa2-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-mempool-dpaa24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-mempool-octeontx24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-mempool-ring24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-mempool-stack24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-mempool24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meta-all', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meta-allpmds', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meta-baseband', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meta-bus', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meta-common', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meta-compress', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meta-crypto', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meta-dma', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meta-event', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meta-mempool', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meta-net', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meta-raw', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-meter24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-metrics24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-ml-cnxk24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-mldev24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-af-packet24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-af-xdp24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-ark24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-atlantic24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-avp24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-axgbe24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-bnx2x24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-bnxt24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-bond24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-cnxk24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-cpfl24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-cxgbe24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-dpaa2-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-dpaa24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-e1000-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-ena24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-enetc24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-enetfec24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-enic24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-failsafe24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-fm10k24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-gve24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-hinic24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-hns3-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-i40e24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-iavf24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-ice24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-idpf24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-igc24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-ionic24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-ipn3ke24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-ixgbe24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-mana24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-memif24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-mlx4-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-mlx5-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-netvsc24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-nfp24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-ngbe24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-null24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-octeon-ep24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-octeontx24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-pcap24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-pfe24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-qede24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-ring24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-sfc24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-softnic24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-tap24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-thunderx24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-txgbe24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-vdev-netvsc24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-vhost24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-virtio24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net-vmxnet3-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-net24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-node24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-pcapng24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-pci24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-pdcp24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-pdump24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-pipeline24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-port24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-power24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-raw-cnxk-bphy24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-raw-cnxk-gpio24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-raw-dpaa2-cmdif24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-raw-ifpga24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-raw-ntb24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-raw-skeleton24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-rawdev24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-rcu24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-regex-cn9k24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-regex-mlx5-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-regexdev24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-reorder24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-rib24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-ring24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-sched24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-security24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-stack24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-table24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-telemetry24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-timer24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-vdpa-ifc24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-vdpa-mlx5-24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-vdpa-nfp24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-vdpa-sfc24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.04', 'pkgname': 'librte-vhost24', 'pkgver': '23.11-1ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'dpdk', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'dpdk-dev', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'libdpdk-dev', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-acl24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-baseband-acc24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-baseband-fpga-5gnr-fec24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-baseband-fpga-lte-fec24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-baseband-la12xx24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-baseband-null24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-baseband-turbo-sw24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-bbdev24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-bitratestats24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-bpf24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-bus-auxiliary24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-bus-cdx24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-bus-dpaa24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-bus-fslmc24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-bus-ifpga24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-bus-pci24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-bus-platform24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-bus-vdev24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-bus-vmbus24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-cfgfile24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-cmdline24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-common-cnxk24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-common-cpt24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-common-dpaax24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-common-iavf24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-common-idpf24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-common-mlx5-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-common-nfp24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-common-octeontx24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-common-qat24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-common-sfc-efx24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-compress-isal24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-compress-mlx5-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-compress-octeontx24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-compress-zlib24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-compressdev24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-bcmfs24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-caam-jr24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-ccp24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-cnxk24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-dpaa-sec24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-dpaa2-sec24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-ipsec-mb24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-mlx5-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-nitrox24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-null24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-octeontx24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-openssl24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-scheduler24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-crypto-virtio24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-cryptodev24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-dispatcher24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-distributor24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-dma-cnxk24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-dma-dpaa2-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-dma-dpaa24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-dma-hisilicon24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-dma-idxd24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-dma-ioat24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-dma-skeleton24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-dmadev24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-eal24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-efd24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-ethdev24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-event-cnxk24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-event-dlb2-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-event-dpaa2-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-event-dpaa24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-event-dsw24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-event-octeontx24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-event-opdl24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-event-skeleton24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-event-sw24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-eventdev24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-fib24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-gpudev24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-graph24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-gro24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-gso24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-hash24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-ip-frag24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-ipsec24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-jobstats24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-kvargs24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-latencystats24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-log24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-lpm24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-mbuf24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-member24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-mempool-bucket24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-mempool-cnxk24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-mempool-dpaa2-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-mempool-dpaa24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-mempool-octeontx24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-mempool-ring24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-mempool-stack24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-mempool24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meta-all', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meta-allpmds', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meta-baseband', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meta-bus', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meta-common', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meta-compress', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meta-crypto', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meta-dma', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meta-event', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meta-mempool', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meta-net', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meta-raw', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-meter24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-metrics24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-ml-cnxk24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-mldev24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-af-packet24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-af-xdp24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-ark24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-atlantic24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-avp24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-axgbe24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-bnx2x24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-bnxt24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-bond24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-cnxk24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-cpfl24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-cxgbe24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-dpaa2-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-dpaa24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-e1000-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-ena24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-enetc24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-enetfec24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-enic24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-failsafe24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-fm10k24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-gve24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-hinic24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-hns3-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-i40e24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-iavf24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-ice24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-idpf24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-igc24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-ionic24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-ipn3ke24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-ixgbe24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-mana24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-memif24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-mlx4-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-mlx5-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-netvsc24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-nfp24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-ngbe24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-null24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-octeon-ep24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-octeontx24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-pcap24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-pfe24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-qede24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-ring24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-sfc24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-softnic24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-tap24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-thunderx24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-txgbe24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-vdev-netvsc24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-vhost24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-virtio24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net-vmxnet3-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-net24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-node24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-pcapng24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-pci24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-pdcp24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-pdump24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-pipeline24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-port24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-power24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-raw-cnxk-bphy24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-raw-cnxk-gpio24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-raw-dpaa2-cmdif24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-raw-ifpga24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-raw-ntb24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-raw-skeleton24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-rawdev24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-rcu24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-regex-cn9k24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-regex-mlx5-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-regexdev24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-reorder24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-rib24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-ring24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-sched24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-security24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-stack24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-table24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-telemetry24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-timer24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-vdpa-ifc24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-vdpa-mlx5-24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-vdpa-nfp24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-vdpa-sfc24', 'pkgver': '23.11.2-0ubuntu1.1'},
    {'osver': '24.10', 'pkgname': 'librte-vhost24', 'pkgver': '23.11.2-0ubuntu1.1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  var extra = '';
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dpdk / dpdk-dev / libdpdk-dev / librte-acl22 / librte-acl24 / etc');
}
