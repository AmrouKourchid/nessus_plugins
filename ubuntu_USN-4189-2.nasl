#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4189-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131313);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");
  script_xref(name:"USN", value:"4189-2");

  script_name(english:"Ubuntu 18.04 LTS : DPDK regression (USN-4189-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-4189-2 advisory.

    USN-4189-1 fixed a vulnerability in DPDK. The new version introduced a regression in certain environments.
    This update fixes the problem.



Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4189-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk-igb-uio-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk-rte-kni-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-acl17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bitratestats17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-pci17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-vdev17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cfgfile17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cmdline17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cryptodev17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-distributor17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eal17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-efd17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ethdev17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eventdev17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-flow-classify17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gro17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gso17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-hash17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ip-frag17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-jobstats17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kni17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kvargs17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-latencystats17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-lpm17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mbuf17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-member17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-octeontx17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-ring17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-stack17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meter17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-metrics17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pci17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pdump17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pipeline17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-af-packet17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ark17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-avp17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bnxt17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bond17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-crypto-scheduler17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-cxgbe17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-e1000-17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ena17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-enic17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-failsafe17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-fm10k17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-i40e17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ixgbe17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-kni17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-lio17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-mlx4-17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-mlx5-17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-nfp17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-null-crypto17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-null17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx-ssovf17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-pcap17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-qede17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ring17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-sfc-efx17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-skeleton-event17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-softnic17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-sw-event17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-tap17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-thunderx-nicvf17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-vhost17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-virtio17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-vmxnet3-uio17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-port17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-power17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-reorder17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ring17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-sched17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-security17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-table17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-timer17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vhost17.11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2024 Canonical, Inc. / NASL script (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'dpdk', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'dpdk-dev', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'dpdk-igb-uio-dkms', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'dpdk-rte-kni-dkms', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'libdpdk-dev', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-acl17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-bitratestats17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-bus-pci17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-bus-vdev17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-cfgfile17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-cmdline17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-cryptodev17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-distributor17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-eal17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-efd17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-ethdev17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-eventdev17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-flow-classify17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-gro17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-gso17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-hash17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-ip-frag17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-jobstats17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-kni17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-kvargs17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-latencystats17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-lpm17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-mbuf17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-member17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-mempool-octeontx17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-mempool-ring17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-mempool-stack17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-mempool17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-meter17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-metrics17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-net17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pci17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pdump17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pipeline17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-af-packet17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-ark17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-avp17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-bnxt17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-bond17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-crypto-scheduler17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-cxgbe17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-e1000-17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-ena17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-enic17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-failsafe17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-fm10k17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-i40e17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-ixgbe17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-kni17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-lio17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-mlx4-17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-mlx5-17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-nfp17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-null-crypto17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-null17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-octeontx-ssovf17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-octeontx17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-pcap17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-qede17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-ring17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-sfc-efx17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-skeleton-event17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-softnic17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-sw-event17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-tap17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-thunderx-nicvf17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-vhost17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-virtio17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-vmxnet3-uio17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-port17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-power17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-reorder17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-ring17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-sched17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-security17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-table17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-timer17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'librte-vhost17.11', 'pkgver': '17.11.9-0ubuntu18.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dpdk / dpdk-dev / dpdk-igb-uio-dkms / dpdk-rte-kni-dkms / etc');
}
