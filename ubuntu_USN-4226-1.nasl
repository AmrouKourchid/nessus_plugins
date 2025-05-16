#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4226-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132690);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2019-10220",
    "CVE-2019-14895",
    "CVE-2019-14896",
    "CVE-2019-14897",
    "CVE-2019-14901",
    "CVE-2019-16231",
    "CVE-2019-16233",
    "CVE-2019-17075",
    "CVE-2019-17133",
    "CVE-2019-18660",
    "CVE-2019-18813",
    "CVE-2019-19045",
    "CVE-2019-19048",
    "CVE-2019-19052",
    "CVE-2019-19055",
    "CVE-2019-19060",
    "CVE-2019-19065",
    "CVE-2019-19067",
    "CVE-2019-19072",
    "CVE-2019-19075",
    "CVE-2019-19083",
    "CVE-2019-19524",
    "CVE-2019-19526",
    "CVE-2019-19529",
    "CVE-2019-19532",
    "CVE-2019-19534",
    "CVE-2019-19922",
    "CVE-2019-2214"
  );
  script_xref(name:"USN", value:"4226-1");

  script_name(english:"Ubuntu 18.04 LTS : Linux kernel vulnerabilities (USN-4226-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4226-1 advisory.

    Michael Hanselmann discovered that the CIFS implementation in the Linux kernel did not sanitize paths
    returned by an SMB server. An attacker controlling an SMB server could use this to overwrite arbitrary
    files. (CVE-2019-10220)

    It was discovered that a heap-based buffer overflow existed in the Marvell WiFi-Ex Driver for the Linux
    kernel. A physically proximate attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2019-14895, CVE-2019-14901)

    It was discovered that a heap-based buffer overflow existed in the Marvell Libertas WLAN Driver for the
    Linux kernel. A physically proximate attacker could use this to cause a denial of service (system crash)
    or possibly execute arbitrary code. (CVE-2019-14896, CVE-2019-14897)

    It was discovered that the Fujitsu ES network device driver for the Linux kernel did not properly check
    for errors in some situations, leading to a NULL pointer dereference. A local attacker could use this to
    cause a denial of service. (CVE-2019-16231)

    It was discovered that the QLogic Fibre Channel driver in the Linux kernel did not properly check for
    error, leading to a NULL pointer dereference. A local attacker could possibly use this to cause a denial
    of service (system crash). (CVE-2019-16233)

    Nicolas Waisman discovered that the WiFi driver stack in the Linux kernel did not properly validate SSID
    lengths. A physically proximate attacker could use this to cause a denial of service (system crash).
    (CVE-2019-17133)

    Anthony Steinhauser discovered that the Linux kernel did not properly perform Spectre_RSB mitigations to
    all processors for PowerPC architecture systems in some situations. A local attacker could use this to
    expose sensitive information. (CVE-2019-18660)

    It was discovered that the Mellanox Technologies Innova driver in the Linux kernel did not properly
    deallocate memory in certain failure conditions. A local attacker could use this to cause a denial of
    service (kernel memory exhaustion). (CVE-2019-19045)

    It was discovered that the VirtualBox guest driver implementation in the Linux kernel did not properly
    deallocate memory in certain error conditions. A local attacker could use this to cause a denial of
    service (memory exhaustion). (CVE-2019-19048)

    It was discovered that Geschwister Schneider USB CAN interface driver in the Linux kernel did not properly
    deallocate memory in certain failure conditions. A physically proximate attacker could use this to cause a
    denial of service (kernel memory exhaustion). (CVE-2019-19052)

    It was discovered that the netlink-based 802.11 configuration interface in the Linux kernel did not
    deallocate memory in certain error conditions. A local attacker could possibly use this to cause a denial
    of service (kernel memory exhaustion). (CVE-2019-19055)

    It was discovered that the ADIS16400 IIO IMU Driver for the Linux kernel did not properly deallocate
    memory in certain error conditions. A local attacker could use this to cause a denial of service (memory
    exhaustion). (CVE-2019-19060)

    It was discovered that the Intel OPA Gen1 Infiniband Driver for the Linux kernel did not properly
    deallocate memory in certain error conditions. A local attacker could use this to cause a denial of
    service (memory exhaustion). (CVE-2019-19065)

    It was discovered that the AMD Audio Coprocessor driver for the Linux kernel did not properly deallocate
    memory in certain error conditions. A local attacker with the ability to load modules could use this to
    cause a denial of service (memory exhaustion). (CVE-2019-19067)

    It was discovered that the event tracing subsystem of the Linux kernel did not properly deallocate memory
    in certain error conditions. A local attacker could use this to cause a denial of service (kernel memory
    exhaustion). (CVE-2019-19072)

    It was discovered that the Cascoda CA8210 SPI 802.15.4 wireless controller driver for the Linux kernel did
    not properly deallocate memory in certain error conditions. A local attacker could use this to cause a
    denial of service (memory exhaustion). (CVE-2019-19075)

    It was discovered that the AMD Display Engine Driver in the Linux kernel did not properly deallocate
    memory in certain error conditions. A local attack could use this to cause a denial of service (memory
    exhaustion). (CVE-2019-19083)

    It was discovered that the driver for memoryless force-feedback input devices in the Linux kernel
    contained a use-after-free vulnerability. A physically proximate attacker could possibly use this to cause
    a denial of service (system crash) or execute arbitrary code. (CVE-2019-19524)

    It was discovered that the NXP PN533 NFC USB driver in the Linux kernel did not properly free resources
    after a late probe error, leading to a use- after-free vulnerability. A physically proximate attacker
    could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2019-19526)

    It was discovered that the Microchip CAN BUS Analyzer driver in the Linux kernel contained a use-after-
    free vulnerability on device disconnect. A physically proximate attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2019-19529)

    It was discovered that multiple USB HID device drivers in the Linux kernel did not properly validate
    device metadata on attachment, leading to out-of- bounds writes. A physically proximate attacker could use
    this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2019-19532)

    It was discovered that the PEAK-System Technik USB driver in the Linux kernel did not properly sanitize
    memory before sending it to the device. A physically proximate attacker could use this to expose sensitive
    information (kernel memory). (CVE-2019-19534)

    It was discovered that in some situations the fair scheduler in the Linux kernel did not permit a process
    to use its full quota time slice. A local attacker could use this to cause a denial of service.
    (CVE-2019-19922)

    It was discovered that the binder IPC implementation in the Linux kernel did not properly perform bounds
    checking in some situations, leading to an out-of-bounds write. A local attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2019-2214)

    Nicolas Waisman discovered that the Chelsio T4/T5 RDMA Driver for the Linux kernel performed DMA from a
    kernel stack. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2019-17075)

    It was discovered that the DesignWare USB3 controller driver in the Linux kernel did not properly
    deallocate memory in some error conditions. A local attacker could possibly use this to cause a denial of
    service (memory exhaustion). (CVE-2019-18813)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4226-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14901");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0.0-1009-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0.0-1023-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0.0-1027-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0.0-1028-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0.0-1033-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '18.04': {
    '5.0.0': {
      'oracle': '5.0.0-1009',
      'aws': '5.0.0-1023',
      'gke': '5.0.0-1027',
      'azure': '5.0.0-1028',
      'oem-osp1': '5.0.0-1033'
    }
  }
};

var host_kernel_release = get_kb_item('Host/uptrack-uname-r');
if (empty_or_null(host_kernel_release)) host_kernel_release = get_kb_item_or_exit('Host/uname-r');
var host_kernel_base_version = get_kb_item_or_exit('Host/Debian/kernel-base-version');
var host_kernel_type = get_kb_item_or_exit('Host/Debian/kernel-type');
if(empty_or_null(kernel_mappings[os_release][host_kernel_base_version][host_kernel_type])) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + host_kernel_release);

var extra = '';
var kernel_fixed_version = kernel_mappings[os_release][host_kernel_base_version][host_kernel_type] + "-" + host_kernel_type;
if (deb_ver_cmp(ver1:host_kernel_release, ver2:kernel_fixed_version) < 0)
{
  extra += 'Running Kernel level of ' + host_kernel_release + ' does not meet the minimum fixed level of ' + kernel_fixed_version + ' for this advisory.\n\n';
}
  else
{
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4226-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2019-2214', 'CVE-2019-10220', 'CVE-2019-14895', 'CVE-2019-14896', 'CVE-2019-14897', 'CVE-2019-14901', 'CVE-2019-16231', 'CVE-2019-16233', 'CVE-2019-17075', 'CVE-2019-17133', 'CVE-2019-18660', 'CVE-2019-18813', 'CVE-2019-19045', 'CVE-2019-19048', 'CVE-2019-19052', 'CVE-2019-19055', 'CVE-2019-19060', 'CVE-2019-19065', 'CVE-2019-19067', 'CVE-2019-19072', 'CVE-2019-19075', 'CVE-2019-19083', 'CVE-2019-19524', 'CVE-2019-19526', 'CVE-2019-19529', 'CVE-2019-19532', 'CVE-2019-19534', 'CVE-2019-19922');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4226-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
