#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6896-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202292);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id(
    "CVE-2022-48627",
    "CVE-2023-6270",
    "CVE-2023-7042",
    "CVE-2023-52620",
    "CVE-2023-52644",
    "CVE-2023-52650",
    "CVE-2023-52656",
    "CVE-2023-52699",
    "CVE-2023-52880",
    "CVE-2024-22099",
    "CVE-2024-23307",
    "CVE-2024-24857",
    "CVE-2024-24858",
    "CVE-2024-24859",
    "CVE-2024-24861",
    "CVE-2024-25739",
    "CVE-2024-26586",
    "CVE-2024-26642",
    "CVE-2024-26643",
    "CVE-2024-26651",
    "CVE-2024-26654",
    "CVE-2024-26687",
    "CVE-2024-26810",
    "CVE-2024-26812",
    "CVE-2024-26813",
    "CVE-2024-26816",
    "CVE-2024-26817",
    "CVE-2024-26820",
    "CVE-2024-26828",
    "CVE-2024-26851",
    "CVE-2024-26852",
    "CVE-2024-26855",
    "CVE-2024-26857",
    "CVE-2024-26859",
    "CVE-2024-26862",
    "CVE-2024-26863",
    "CVE-2024-26874",
    "CVE-2024-26875",
    "CVE-2024-26878",
    "CVE-2024-26880",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26889",
    "CVE-2024-26894",
    "CVE-2024-26898",
    "CVE-2024-26901",
    "CVE-2024-26903",
    "CVE-2024-26922",
    "CVE-2024-26923",
    "CVE-2024-26925",
    "CVE-2024-26926",
    "CVE-2024-26931",
    "CVE-2024-26934",
    "CVE-2024-26935",
    "CVE-2024-26937",
    "CVE-2024-26955",
    "CVE-2024-26956",
    "CVE-2024-26957",
    "CVE-2024-26965",
    "CVE-2024-26966",
    "CVE-2024-26969",
    "CVE-2024-26973",
    "CVE-2024-26974",
    "CVE-2024-26976",
    "CVE-2024-26981",
    "CVE-2024-26984",
    "CVE-2024-26993",
    "CVE-2024-26994",
    "CVE-2024-26999",
    "CVE-2024-27000",
    "CVE-2024-27001",
    "CVE-2024-27004",
    "CVE-2024-27008",
    "CVE-2024-27013",
    "CVE-2024-27020",
    "CVE-2024-27024",
    "CVE-2024-27028",
    "CVE-2024-27030",
    "CVE-2024-27038",
    "CVE-2024-27043",
    "CVE-2024-27044",
    "CVE-2024-27046",
    "CVE-2024-27053",
    "CVE-2024-27059",
    "CVE-2024-27065",
    "CVE-2024-27073",
    "CVE-2024-27074",
    "CVE-2024-27075",
    "CVE-2024-27076",
    "CVE-2024-27077",
    "CVE-2024-27078",
    "CVE-2024-27388",
    "CVE-2024-27395",
    "CVE-2024-27396",
    "CVE-2024-27419",
    "CVE-2024-27436",
    "CVE-2024-27437",
    "CVE-2024-35789",
    "CVE-2024-35805",
    "CVE-2024-35806",
    "CVE-2024-35807",
    "CVE-2024-35809",
    "CVE-2024-35813",
    "CVE-2024-35815",
    "CVE-2024-35819",
    "CVE-2024-35821",
    "CVE-2024-35822",
    "CVE-2024-35823",
    "CVE-2024-35825",
    "CVE-2024-35828",
    "CVE-2024-35830",
    "CVE-2024-35847",
    "CVE-2024-35849",
    "CVE-2024-35852",
    "CVE-2024-35853",
    "CVE-2024-35854",
    "CVE-2024-35855",
    "CVE-2024-35877",
    "CVE-2024-35886",
    "CVE-2024-35888",
    "CVE-2024-35893",
    "CVE-2024-35895",
    "CVE-2024-35897",
    "CVE-2024-35898",
    "CVE-2024-35899",
    "CVE-2024-35900",
    "CVE-2024-35910",
    "CVE-2024-35915",
    "CVE-2024-35922",
    "CVE-2024-35925",
    "CVE-2024-35930",
    "CVE-2024-35933",
    "CVE-2024-35935",
    "CVE-2024-35936",
    "CVE-2024-35944",
    "CVE-2024-35950",
    "CVE-2024-35955",
    "CVE-2024-35960",
    "CVE-2024-35969",
    "CVE-2024-35973",
    "CVE-2024-35978",
    "CVE-2024-35982",
    "CVE-2024-35984",
    "CVE-2024-35997",
    "CVE-2024-36004",
    "CVE-2024-36006",
    "CVE-2024-36007",
    "CVE-2024-36020"
  );
  script_xref(name:"USN", value:"6896-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-6896-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6896-1 advisory.

    It was discovered that the ATA over Ethernet (AoE) driver in the Linux kernel contained a race condition,
    leading to a use-after-free vulnerability. An attacker could use this to cause a denial of service or
    possibly execute arbitrary code. (CVE-2023-6270)

    It was discovered that the Atheros 802.11ac wireless driver did not properly validate certain data
    structures, leading to a NULL pointer dereference. An attacker could possibly use this to cause a denial
    of service. (CVE-2023-7042)

    Yuxuan Hu discovered that the Bluetooth RFCOMM protocol driver in the Linux Kernel contained a race
    condition, leading to a NULL pointer dereference. An attacker could possibly use this to cause a denial of
    service (system crash). (CVE-2024-22099)

    Gui-Dong Han discovered that the software RAID driver in the Linux kernel contained a race condition,
    leading to an integer overflow vulnerability. A privileged attacker could possibly use this to cause a
    denial of service (system crash). (CVE-2024-23307)

    It was discovered that a race condition existed in the Bluetooth subsystem in the Linux kernel when
    modifying certain settings values through debugfs. A privileged local attacker could use this to cause a
    denial of service. (CVE-2024-24857, CVE-2024-24858, CVE-2024-24859)

    Bai Jiaju discovered that the Xceive XC4000 silicon tuner device driver in the Linux kernel contained a
    race condition, leading to an integer overflow vulnerability. An attacker could possibly use this to cause
    a denial of service (system crash). (CVE-2024-24861)

    Chenyuan Yang discovered that the Unsorted Block Images (UBI) flash device volume management subsystem did
    not properly validate logical eraseblock sizes in certain situations. An attacker could possibly use this
    to cause a denial of service (system crash). (CVE-2024-25739)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - x86 architecture;

    - Block layer subsystem;

    - Accessibility subsystem;

    - ACPI drivers;

    - Android drivers;

    - Bluetooth drivers;

    - Clock framework and drivers;

    - Data acquisition framework and drivers;

    - Cryptographic API;

    - GPU drivers;

    - HID subsystem;

    - I2C subsystem;

    - IRQ chip drivers;

    - Multiple devices driver;

    - Media drivers;

    - VMware VMCI Driver;

    - MMC subsystem;

    - Network drivers;

    - PCI subsystem;

    - SCSI drivers;

    - Freescale SoC drivers;

    - SPI subsystem;

    - Media staging drivers;

    - TTY drivers;

    - USB subsystem;

    - VFIO drivers;

    - Framebuffer layer;

    - Xen hypervisor drivers;

    - File systems infrastructure;

    - BTRFS file system;

    - Ext4 file system;

    - FAT file system;

    - NILFS2 file system;

    - Diskquota system;

    - SMB network file system;

    - UBI file system;

    - io_uring subsystem;

    - BPF subsystem;

    - Core kernel;

    - Memory management;

    - B.A.T.M.A.N. meshing protocol;

    - Bluetooth subsystem;

    - Networking core;

    - HSR network protocol;

    - IPv4 networking;

    - IPv6 networking;

    - MAC80211 subsystem;

    - Netfilter;

    - NET/ROM layer;

    - NFC subsystem;

    - Open vSwitch;

    - Packet sockets;

    - RDS protocol;

    - Network traffic control;

    - Sun RPC protocol;

    - Unix domain sockets;

    - ALSA SH drivers;

    - USB sound devices;

    - KVM core; (CVE-2024-35969, CVE-2024-35819, CVE-2024-26851, CVE-2024-26816, CVE-2024-26643,
    CVE-2023-52656, CVE-2024-27020, CVE-2024-35821, CVE-2024-35930, CVE-2024-35936, CVE-2024-27075,
    CVE-2024-26817, CVE-2024-26984, CVE-2024-35895, CVE-2024-35853, CVE-2024-27043, CVE-2024-35978,
    CVE-2024-35960, CVE-2024-26882, CVE-2024-35806, CVE-2024-35830, CVE-2024-26852, CVE-2024-35915,
    CVE-2024-36006, CVE-2024-35935, CVE-2024-26926, CVE-2024-35877, CVE-2024-27396, CVE-2024-26654,
    CVE-2024-27077, CVE-2024-27078, CVE-2024-27000, CVE-2024-35888, CVE-2024-27437, CVE-2024-26994,
    CVE-2024-26973, CVE-2024-26687, CVE-2024-26955, CVE-2024-26898, CVE-2024-26859, CVE-2023-52620,
    CVE-2024-35893, CVE-2024-26903, CVE-2024-26862, CVE-2024-35950, CVE-2023-52644, CVE-2024-26969,
    CVE-2024-27028, CVE-2024-35984, CVE-2024-36007, CVE-2024-35925, CVE-2024-36020, CVE-2024-26956,
    CVE-2024-35789, CVE-2024-26878, CVE-2024-35855, CVE-2024-35822, CVE-2023-52699, CVE-2024-27044,
    CVE-2024-27030, CVE-2024-27065, CVE-2024-26993, CVE-2024-27395, CVE-2024-27013, CVE-2024-35922,
    CVE-2024-26586, CVE-2024-36004, CVE-2024-35897, CVE-2024-35807, CVE-2024-26901, CVE-2024-27076,
    CVE-2023-52880, CVE-2022-48627, CVE-2024-26894, CVE-2023-52650, CVE-2024-27001, CVE-2024-26863,
    CVE-2024-26651, CVE-2024-35886, CVE-2024-35982, CVE-2024-26883, CVE-2024-26935, CVE-2024-27074,
    CVE-2024-35849, CVE-2024-35955, CVE-2024-26965, CVE-2024-35898, CVE-2024-26855, CVE-2024-35933,
    CVE-2024-35823, CVE-2024-35815, CVE-2024-26880, CVE-2024-26874, CVE-2024-26642, CVE-2024-26937,
    CVE-2024-35854, CVE-2024-35997, CVE-2024-27059, CVE-2024-26812, CVE-2024-26999, CVE-2024-26923,
    CVE-2024-26934, CVE-2024-27024, CVE-2024-27419, CVE-2024-35847, CVE-2024-26974, CVE-2024-26875,
    CVE-2024-35805, CVE-2024-27008, CVE-2024-26889, CVE-2024-27053, CVE-2024-27388, CVE-2024-26981,
    CVE-2024-26976, CVE-2024-35973, CVE-2024-35852, CVE-2024-35809, CVE-2024-27004, CVE-2024-26884,
    CVE-2024-35899, CVE-2024-26931, CVE-2024-35813, CVE-2024-26922, CVE-2024-26957, CVE-2024-35944,
    CVE-2024-27038, CVE-2024-35910, CVE-2024-26925, CVE-2024-26820, CVE-2024-26857, CVE-2024-26828,
    CVE-2024-35825, CVE-2024-26813, CVE-2024-27046, CVE-2024-26810, CVE-2024-27436, CVE-2024-27073,
    CVE-2024-35828, CVE-2024-35900, CVE-2024-26966)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6896-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35855");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1075-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1088-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1095-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1116-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1132-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1133-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-189-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-189-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-189-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var kernel_mappings = {
  '18.04': {
    '5.4.0': {
      'ibm': '5.4.0-1075',
      'gcp': '5.4.0-1132',
      'azure': '5.4.0-1133'
    }
  },
  '20.04': {
    '5.4.0': {
      'generic': '5.4.0-189',
      'generic-lpae': '5.4.0-189',
      'lowlatency': '5.4.0-189',
      'ibm': '5.4.0-1075',
      'bluefield': '5.4.0-1088',
      'gkeop': '5.4.0-1095',
      'kvm': '5.4.0-1116',
      'gcp': '5.4.0-1132',
      'azure': '5.4.0-1133'
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
if (!ubuntu_pro_detected) {
  extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
  extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
  extra += 'require an Ubuntu Pro subscription.\n\n';
}
if (deb_ver_cmp(ver1:host_kernel_release, ver2:kernel_fixed_version) < 0)
{
  extra += 'Running Kernel level of ' + host_kernel_release + ' does not meet the minimum fixed level of ' + kernel_fixed_version + ' for this advisory.\n\n';
}
  else
{
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6896-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-48627', 'CVE-2023-6270', 'CVE-2023-7042', 'CVE-2023-52620', 'CVE-2023-52644', 'CVE-2023-52650', 'CVE-2023-52656', 'CVE-2023-52699', 'CVE-2023-52880', 'CVE-2024-22099', 'CVE-2024-23307', 'CVE-2024-24857', 'CVE-2024-24858', 'CVE-2024-24859', 'CVE-2024-24861', 'CVE-2024-25739', 'CVE-2024-26586', 'CVE-2024-26642', 'CVE-2024-26643', 'CVE-2024-26651', 'CVE-2024-26654', 'CVE-2024-26687', 'CVE-2024-26810', 'CVE-2024-26812', 'CVE-2024-26813', 'CVE-2024-26816', 'CVE-2024-26817', 'CVE-2024-26820', 'CVE-2024-26828', 'CVE-2024-26851', 'CVE-2024-26852', 'CVE-2024-26855', 'CVE-2024-26857', 'CVE-2024-26859', 'CVE-2024-26862', 'CVE-2024-26863', 'CVE-2024-26874', 'CVE-2024-26875', 'CVE-2024-26878', 'CVE-2024-26880', 'CVE-2024-26882', 'CVE-2024-26883', 'CVE-2024-26884', 'CVE-2024-26889', 'CVE-2024-26894', 'CVE-2024-26898', 'CVE-2024-26901', 'CVE-2024-26903', 'CVE-2024-26922', 'CVE-2024-26923', 'CVE-2024-26925', 'CVE-2024-26926', 'CVE-2024-26931', 'CVE-2024-26934', 'CVE-2024-26935', 'CVE-2024-26937', 'CVE-2024-26955', 'CVE-2024-26956', 'CVE-2024-26957', 'CVE-2024-26965', 'CVE-2024-26966', 'CVE-2024-26969', 'CVE-2024-26973', 'CVE-2024-26974', 'CVE-2024-26976', 'CVE-2024-26981', 'CVE-2024-26984', 'CVE-2024-26993', 'CVE-2024-26994', 'CVE-2024-26999', 'CVE-2024-27000', 'CVE-2024-27001', 'CVE-2024-27004', 'CVE-2024-27008', 'CVE-2024-27013', 'CVE-2024-27020', 'CVE-2024-27024', 'CVE-2024-27028', 'CVE-2024-27030', 'CVE-2024-27038', 'CVE-2024-27043', 'CVE-2024-27044', 'CVE-2024-27046', 'CVE-2024-27053', 'CVE-2024-27059', 'CVE-2024-27065', 'CVE-2024-27073', 'CVE-2024-27074', 'CVE-2024-27075', 'CVE-2024-27076', 'CVE-2024-27077', 'CVE-2024-27078', 'CVE-2024-27388', 'CVE-2024-27395', 'CVE-2024-27396', 'CVE-2024-27419', 'CVE-2024-27436', 'CVE-2024-27437', 'CVE-2024-35789', 'CVE-2024-35805', 'CVE-2024-35806', 'CVE-2024-35807', 'CVE-2024-35809', 'CVE-2024-35813', 'CVE-2024-35815', 'CVE-2024-35819', 'CVE-2024-35821', 'CVE-2024-35822', 'CVE-2024-35823', 'CVE-2024-35825', 'CVE-2024-35828', 'CVE-2024-35830', 'CVE-2024-35847', 'CVE-2024-35849', 'CVE-2024-35852', 'CVE-2024-35853', 'CVE-2024-35854', 'CVE-2024-35855', 'CVE-2024-35877', 'CVE-2024-35886', 'CVE-2024-35888', 'CVE-2024-35893', 'CVE-2024-35895', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-35899', 'CVE-2024-35900', 'CVE-2024-35910', 'CVE-2024-35915', 'CVE-2024-35922', 'CVE-2024-35925', 'CVE-2024-35930', 'CVE-2024-35933', 'CVE-2024-35935', 'CVE-2024-35936', 'CVE-2024-35944', 'CVE-2024-35950', 'CVE-2024-35955', 'CVE-2024-35960', 'CVE-2024-35969', 'CVE-2024-35973', 'CVE-2024-35978', 'CVE-2024-35982', 'CVE-2024-35984', 'CVE-2024-35997', 'CVE-2024-36004', 'CVE-2024-36006', 'CVE-2024-36007', 'CVE-2024-36020');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6896-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
