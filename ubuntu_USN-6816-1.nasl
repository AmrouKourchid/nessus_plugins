#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6816-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200227);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/04");

  script_cve_id(
    "CVE-2022-38096",
    "CVE-2022-48669",
    "CVE-2023-6270",
    "CVE-2023-7042",
    "CVE-2023-47233",
    "CVE-2023-52644",
    "CVE-2023-52647",
    "CVE-2023-52648",
    "CVE-2023-52649",
    "CVE-2023-52650",
    "CVE-2023-52652",
    "CVE-2023-52653",
    "CVE-2023-52659",
    "CVE-2023-52661",
    "CVE-2023-52662",
    "CVE-2023-52663",
    "CVE-2024-21823",
    "CVE-2024-23307",
    "CVE-2024-24861",
    "CVE-2024-25739",
    "CVE-2024-26651",
    "CVE-2024-26653",
    "CVE-2024-26654",
    "CVE-2024-26655",
    "CVE-2024-26656",
    "CVE-2024-26657",
    "CVE-2024-26809",
    "CVE-2024-26810",
    "CVE-2024-26812",
    "CVE-2024-26813",
    "CVE-2024-26814",
    "CVE-2024-26815",
    "CVE-2024-26816",
    "CVE-2024-26848",
    "CVE-2024-26859",
    "CVE-2024-26860",
    "CVE-2024-26861",
    "CVE-2024-26862",
    "CVE-2024-26863",
    "CVE-2024-26864",
    "CVE-2024-26865",
    "CVE-2024-26866",
    "CVE-2024-26868",
    "CVE-2024-26869",
    "CVE-2024-26870",
    "CVE-2024-26871",
    "CVE-2024-26872",
    "CVE-2024-26873",
    "CVE-2024-26874",
    "CVE-2024-26875",
    "CVE-2024-26876",
    "CVE-2024-26877",
    "CVE-2024-26878",
    "CVE-2024-26879",
    "CVE-2024-26880",
    "CVE-2024-26881",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26885",
    "CVE-2024-26886",
    "CVE-2024-26887",
    "CVE-2024-26888",
    "CVE-2024-26889",
    "CVE-2024-26890",
    "CVE-2024-26891",
    "CVE-2024-26892",
    "CVE-2024-26893",
    "CVE-2024-26894",
    "CVE-2024-26895",
    "CVE-2024-26896",
    "CVE-2024-26897",
    "CVE-2024-26898",
    "CVE-2024-26899",
    "CVE-2024-26900",
    "CVE-2024-26901",
    "CVE-2024-26927",
    "CVE-2024-26929",
    "CVE-2024-26930",
    "CVE-2024-26931",
    "CVE-2024-26932",
    "CVE-2024-26933",
    "CVE-2024-26934",
    "CVE-2024-26935",
    "CVE-2024-26937",
    "CVE-2024-26938",
    "CVE-2024-26939",
    "CVE-2024-26940",
    "CVE-2024-26941",
    "CVE-2024-26942",
    "CVE-2024-26943",
    "CVE-2024-26944",
    "CVE-2024-26945",
    "CVE-2024-26946",
    "CVE-2024-26947",
    "CVE-2024-26948",
    "CVE-2024-26949",
    "CVE-2024-26950",
    "CVE-2024-26951",
    "CVE-2024-26952",
    "CVE-2024-26953",
    "CVE-2024-26954",
    "CVE-2024-26955",
    "CVE-2024-26956",
    "CVE-2024-26957",
    "CVE-2024-26958",
    "CVE-2024-26959",
    "CVE-2024-26960",
    "CVE-2024-26961",
    "CVE-2024-26962",
    "CVE-2024-26963",
    "CVE-2024-26964",
    "CVE-2024-26965",
    "CVE-2024-26966",
    "CVE-2024-26967",
    "CVE-2024-26968",
    "CVE-2024-26969",
    "CVE-2024-26970",
    "CVE-2024-26971",
    "CVE-2024-26972",
    "CVE-2024-26973",
    "CVE-2024-26975",
    "CVE-2024-26976",
    "CVE-2024-26977",
    "CVE-2024-26978",
    "CVE-2024-26979",
    "CVE-2024-27026",
    "CVE-2024-27027",
    "CVE-2024-27028",
    "CVE-2024-27029",
    "CVE-2024-27030",
    "CVE-2024-27031",
    "CVE-2024-27032",
    "CVE-2024-27033",
    "CVE-2024-27034",
    "CVE-2024-27035",
    "CVE-2024-27036",
    "CVE-2024-27037",
    "CVE-2024-27038",
    "CVE-2024-27039",
    "CVE-2024-27040",
    "CVE-2024-27041",
    "CVE-2024-27042",
    "CVE-2024-27043",
    "CVE-2024-27044",
    "CVE-2024-27045",
    "CVE-2024-27046",
    "CVE-2024-27047",
    "CVE-2024-27048",
    "CVE-2024-27049",
    "CVE-2024-27050",
    "CVE-2024-27051",
    "CVE-2024-27052",
    "CVE-2024-27053",
    "CVE-2024-27054",
    "CVE-2024-27058",
    "CVE-2024-27063",
    "CVE-2024-27064",
    "CVE-2024-27065",
    "CVE-2024-27066",
    "CVE-2024-27067",
    "CVE-2024-27068",
    "CVE-2024-27069",
    "CVE-2024-27070",
    "CVE-2024-27071",
    "CVE-2024-27072",
    "CVE-2024-27073",
    "CVE-2024-27074",
    "CVE-2024-27075",
    "CVE-2024-27076",
    "CVE-2024-27077",
    "CVE-2024-27078",
    "CVE-2024-27079",
    "CVE-2024-27080",
    "CVE-2024-27388",
    "CVE-2024-27389",
    "CVE-2024-27390",
    "CVE-2024-27391",
    "CVE-2024-27392",
    "CVE-2024-27432",
    "CVE-2024-27433",
    "CVE-2024-27434",
    "CVE-2024-27435",
    "CVE-2024-27436",
    "CVE-2024-27437",
    "CVE-2024-35787",
    "CVE-2024-35788",
    "CVE-2024-35789",
    "CVE-2024-35793",
    "CVE-2024-35794",
    "CVE-2024-35795",
    "CVE-2024-35796",
    "CVE-2024-35797",
    "CVE-2024-35798",
    "CVE-2024-35799",
    "CVE-2024-35800",
    "CVE-2024-35801",
    "CVE-2024-35803",
    "CVE-2024-35805",
    "CVE-2024-35806",
    "CVE-2024-35807",
    "CVE-2024-35808",
    "CVE-2024-35809",
    "CVE-2024-35810",
    "CVE-2024-35811",
    "CVE-2024-35813",
    "CVE-2024-35814",
    "CVE-2024-35817",
    "CVE-2024-35819",
    "CVE-2024-35821",
    "CVE-2024-35822",
    "CVE-2024-35826",
    "CVE-2024-35827",
    "CVE-2024-35828",
    "CVE-2024-35829",
    "CVE-2024-35830",
    "CVE-2024-35831",
    "CVE-2024-35843",
    "CVE-2024-35844",
    "CVE-2024-35845",
    "CVE-2024-35874"
  );
  script_xref(name:"USN", value:"6816-1");

  script_name(english:"Ubuntu 24.04 LTS : Linux kernel vulnerabilities (USN-6816-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 24.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6816-1 advisory.

    Ziming Zhang discovered that the DRM driver for VMware Virtual GPU did not properly handle certain error
    conditions, leading to a NULL pointer dereference. A local attacker could possibly trigger this
    vulnerability to cause a denial of service. (CVE-2022-38096)

    Zheng Wang discovered that the Broadcom FullMAC WLAN driver in the Linux kernel contained a race condition
    during device removal, leading to a use- after-free vulnerability. A physically proximate attacker could
    possibly use this to cause a denial of service (system crash). (CVE-2023-47233)

    It was discovered that the ATA over Ethernet (AoE) driver in the Linux kernel contained a race condition,
    leading to a use-after-free vulnerability. An attacker could use this to cause a denial of service or
    possibly execute arbitrary code. (CVE-2023-6270)

    It was discovered that the Atheros 802.11ac wireless driver did not properly validate certain data
    structures, leading to a NULL pointer dereference. An attacker could possibly use this to cause a denial
    of service. (CVE-2023-7042)

    It was discovered that the Intel Data Streaming and Intel Analytics Accelerator drivers in the Linux
    kernel allowed direct access to the devices for unprivileged users and virtual machines. A local attacker
    could use this to cause a denial of service. (CVE-2024-21823)

    Gui-Dong Han discovered that the software RAID driver in the Linux kernel contained a race condition,
    leading to an integer overflow vulnerability. A privileged attacker could possibly use this to cause a
    denial of service (system crash). (CVE-2024-23307)

    Bai Jiaju discovered that the Xceive XC4000 silicon tuner device driver in the Linux kernel contained a
    race condition, leading to an integer overflow vulnerability. An attacker could possibly use this to cause
    a denial of service (system crash). (CVE-2024-24861)

    Chenyuan Yang discovered that the Unsorted Block Images (UBI) flash device volume management subsystem did
    not properly validate logical eraseblock sizes in certain situations. An attacker could possibly use this
    to cause a denial of service (system crash). (CVE-2024-25739)

    It was discovered that the MediaTek SoC Gigabit Ethernet driver in the Linux kernel contained a race
    condition when stopping the device. A local attacker could possibly use this to cause a denial of service
    (device unavailability). (CVE-2024-27432)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM32 architecture;

    - PowerPC architecture;

    - x86 architecture;

    - Block layer subsystem;

    - ACPI drivers;

    - Bluetooth drivers;

    - Clock framework and drivers;

    - CPU frequency scaling framework;

    - Cryptographic API;

    - DPLL subsystem;

    - ARM SCMI message protocol;

    - EFI core;

    - GPU drivers;

    - InfiniBand drivers;

    - IOMMU subsystem;

    - LED subsystem;

    - Multiple devices driver;

    - Media drivers;

    - MMC subsystem;

    - Network drivers;

    - NTB driver;

    - NVME drivers;

    - PCI subsystem;

    - Powercap sysfs driver;

    - SCSI drivers;

    - Freescale SoC drivers;

    - SPI subsystem;

    - Media staging drivers;

    - Thermal drivers;

    - TTY drivers;

    - USB subsystem;

    - DesignWare USB3 driver;

    - VFIO drivers;

    - Backlight driver;

    - Virtio drivers;

    - Xen hypervisor drivers;

    - AFS file system;

    - File systems infrastructure;

    - BTRFS file system;

    - debug file system;

    - Ext4 file system;

    - F2FS file system;

    - FAT file system;

    - Network file system client;

    - NILFS2 file system;

    - Overlay file system;

    - Pstore file system;

    - Diskquota system;

    - SMB network file system;

    - UBI file system;

    - io_uring subsystem;

    - BPF subsystem;

    - Core kernel;

    - Memory management;

    - Bluetooth subsystem;

    - Networking core;

    - HSR network protocol;

    - IPv4 networking;

    - IPv6 networking;

    - MAC80211 subsystem;

    - IEEE 802.15.4 subsystem;

    - Netfilter;

    - Packet sockets;

    - Network traffic control;

    - Sun RPC protocol;

    - ALSA SH drivers;

    - SOF drivers;

    - USB sound devices;

    - KVM core; (CVE-2024-35822, CVE-2024-26859, CVE-2024-26967, CVE-2024-27053, CVE-2024-27064,
    CVE-2024-27437, CVE-2024-26931, CVE-2024-26870, CVE-2024-26927, CVE-2024-26880, CVE-2024-35789,
    CVE-2024-26929, CVE-2024-27034, CVE-2024-26816, CVE-2024-26896, CVE-2024-26975, CVE-2024-26972,
    CVE-2024-26937, CVE-2024-27032, CVE-2024-26871, CVE-2024-26655, CVE-2024-35829, CVE-2024-26886,
    CVE-2023-52653, CVE-2024-27028, CVE-2024-26877, CVE-2024-26898, CVE-2024-35796, CVE-2024-27065,
    CVE-2024-35807, CVE-2024-26966, CVE-2024-35826, CVE-2024-27067, CVE-2024-27039, CVE-2024-35811,
    CVE-2024-26895, CVE-2024-26814, CVE-2024-26893, CVE-2023-52649, CVE-2024-35801, CVE-2023-52648,
    CVE-2024-27048, CVE-2024-26934, CVE-2024-27049, CVE-2024-26890, CVE-2024-26874, CVE-2022-48669,
    CVE-2023-52661, CVE-2024-27436, CVE-2024-27058, CVE-2024-26935, CVE-2024-26956, CVE-2024-26960,
    CVE-2024-26976, CVE-2024-27041, CVE-2024-26873, CVE-2024-26946, CVE-2024-27080, CVE-2024-27432,
    CVE-2023-52650, CVE-2024-26879, CVE-2023-52647, CVE-2024-27435, CVE-2024-27038, CVE-2024-26951,
    CVE-2024-27390, CVE-2024-26863, CVE-2024-26959, CVE-2024-35794, CVE-2024-26889, CVE-2024-35845,
    CVE-2024-27433, CVE-2024-26961, CVE-2024-35803, CVE-2024-26653, CVE-2024-26939, CVE-2024-26872,
    CVE-2024-26979, CVE-2024-26973, CVE-2024-27029, CVE-2024-35831, CVE-2024-26892, CVE-2024-26888,
    CVE-2024-27074, CVE-2024-35844, CVE-2024-26938, CVE-2024-26953, CVE-2024-27391, CVE-2024-35843,
    CVE-2024-27040, CVE-2024-26875, CVE-2024-27026, CVE-2024-26978, CVE-2024-26882, CVE-2023-52652,
    CVE-2023-52662, CVE-2024-26963, CVE-2024-26962, CVE-2024-27051, CVE-2024-27068, CVE-2024-26881,
    CVE-2024-35800, CVE-2024-26964, CVE-2024-27389, CVE-2024-27043, CVE-2024-26901, CVE-2024-26941,
    CVE-2024-35798, CVE-2024-35799, CVE-2024-26952, CVE-2024-26654, CVE-2024-27046, CVE-2024-35810,
    CVE-2024-27050, CVE-2024-27063, CVE-2024-26954, CVE-2024-26884, CVE-2024-27047, CVE-2024-26932,
    CVE-2024-26883, CVE-2024-26943, CVE-2024-26651, CVE-2024-26815, CVE-2024-26948, CVE-2024-27066,
    CVE-2024-27037, CVE-2024-35806, CVE-2024-26869, CVE-2024-26878, CVE-2024-26810, CVE-2024-35797,
    CVE-2024-27073, CVE-2024-26812, CVE-2024-26933, CVE-2024-26809, CVE-2024-26894, CVE-2024-35813,
    CVE-2024-27033, CVE-2024-26876, CVE-2024-27076, CVE-2024-27045, CVE-2024-27079, CVE-2024-26861,
    CVE-2024-26957, CVE-2024-26864, CVE-2024-26866, CVE-2024-35814, CVE-2024-26813, CVE-2024-27388,
    CVE-2024-27042, CVE-2024-26862, CVE-2024-26968, CVE-2024-26940, CVE-2024-27027, CVE-2024-35793,
    CVE-2024-35874, CVE-2024-27035, CVE-2024-26958, CVE-2024-26887, CVE-2024-35809, CVE-2024-26930,
    CVE-2024-35819, CVE-2024-27392, CVE-2024-35808, CVE-2023-52644, CVE-2024-35828, CVE-2024-26657,
    CVE-2024-26969, CVE-2024-27434, CVE-2024-35821, CVE-2023-52663, CVE-2024-27078, CVE-2024-35787,
    CVE-2024-27044, CVE-2024-26848, CVE-2024-26955, CVE-2024-26899, CVE-2024-27077, CVE-2024-26897,
    CVE-2024-26945, CVE-2024-26885, CVE-2024-27069, CVE-2024-27070, CVE-2024-27054, CVE-2024-35795,
    CVE-2024-35817, CVE-2024-35827, CVE-2024-26656, CVE-2024-26860, CVE-2024-26942, CVE-2023-52659,
    CVE-2024-26865, CVE-2024-26868, CVE-2024-26947, CVE-2024-35788, CVE-2024-26950, CVE-2024-27030,
    CVE-2024-26949, CVE-2024-26900, CVE-2024-26971, CVE-2024-35805, CVE-2024-26977, CVE-2024-26944,
    CVE-2024-27036, CVE-2024-26965, CVE-2024-26891, CVE-2024-27071, CVE-2024-27075, CVE-2024-27072,
    CVE-2024-35830, CVE-2024-27052, CVE-2024-26970, CVE-2024-27031)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6816-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27433");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1005-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1006-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-35-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-35-lowlatency-64k");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024-2025 Canonical, Inc. / NASL script (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '24.04': {
    '6.8.0': {
      'lowlatency': '6.8.0-35',
      'lowlatency-64k': '6.8.0-35',
      'raspi': '6.8.0-1005',
      'ibm': '6.8.0-1006'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6816-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-38096', 'CVE-2022-48669', 'CVE-2023-6270', 'CVE-2023-7042', 'CVE-2023-47233', 'CVE-2023-52644', 'CVE-2023-52647', 'CVE-2023-52648', 'CVE-2023-52649', 'CVE-2023-52650', 'CVE-2023-52652', 'CVE-2023-52653', 'CVE-2023-52659', 'CVE-2023-52661', 'CVE-2023-52662', 'CVE-2023-52663', 'CVE-2024-21823', 'CVE-2024-23307', 'CVE-2024-24861', 'CVE-2024-25739', 'CVE-2024-26651', 'CVE-2024-26653', 'CVE-2024-26654', 'CVE-2024-26655', 'CVE-2024-26656', 'CVE-2024-26657', 'CVE-2024-26809', 'CVE-2024-26810', 'CVE-2024-26812', 'CVE-2024-26813', 'CVE-2024-26814', 'CVE-2024-26815', 'CVE-2024-26816', 'CVE-2024-26848', 'CVE-2024-26859', 'CVE-2024-26860', 'CVE-2024-26861', 'CVE-2024-26862', 'CVE-2024-26863', 'CVE-2024-26864', 'CVE-2024-26865', 'CVE-2024-26866', 'CVE-2024-26868', 'CVE-2024-26869', 'CVE-2024-26870', 'CVE-2024-26871', 'CVE-2024-26872', 'CVE-2024-26873', 'CVE-2024-26874', 'CVE-2024-26875', 'CVE-2024-26876', 'CVE-2024-26877', 'CVE-2024-26878', 'CVE-2024-26879', 'CVE-2024-26880', 'CVE-2024-26881', 'CVE-2024-26882', 'CVE-2024-26883', 'CVE-2024-26884', 'CVE-2024-26885', 'CVE-2024-26886', 'CVE-2024-26887', 'CVE-2024-26888', 'CVE-2024-26889', 'CVE-2024-26890', 'CVE-2024-26891', 'CVE-2024-26892', 'CVE-2024-26893', 'CVE-2024-26894', 'CVE-2024-26895', 'CVE-2024-26896', 'CVE-2024-26897', 'CVE-2024-26898', 'CVE-2024-26899', 'CVE-2024-26900', 'CVE-2024-26901', 'CVE-2024-26927', 'CVE-2024-26929', 'CVE-2024-26930', 'CVE-2024-26931', 'CVE-2024-26932', 'CVE-2024-26933', 'CVE-2024-26934', 'CVE-2024-26935', 'CVE-2024-26937', 'CVE-2024-26938', 'CVE-2024-26939', 'CVE-2024-26940', 'CVE-2024-26941', 'CVE-2024-26942', 'CVE-2024-26943', 'CVE-2024-26944', 'CVE-2024-26945', 'CVE-2024-26946', 'CVE-2024-26947', 'CVE-2024-26948', 'CVE-2024-26949', 'CVE-2024-26950', 'CVE-2024-26951', 'CVE-2024-26952', 'CVE-2024-26953', 'CVE-2024-26954', 'CVE-2024-26955', 'CVE-2024-26956', 'CVE-2024-26957', 'CVE-2024-26958', 'CVE-2024-26959', 'CVE-2024-26960', 'CVE-2024-26961', 'CVE-2024-26962', 'CVE-2024-26963', 'CVE-2024-26964', 'CVE-2024-26965', 'CVE-2024-26966', 'CVE-2024-26967', 'CVE-2024-26968', 'CVE-2024-26969', 'CVE-2024-26970', 'CVE-2024-26971', 'CVE-2024-26972', 'CVE-2024-26973', 'CVE-2024-26975', 'CVE-2024-26976', 'CVE-2024-26977', 'CVE-2024-26978', 'CVE-2024-26979', 'CVE-2024-27026', 'CVE-2024-27027', 'CVE-2024-27028', 'CVE-2024-27029', 'CVE-2024-27030', 'CVE-2024-27031', 'CVE-2024-27032', 'CVE-2024-27033', 'CVE-2024-27034', 'CVE-2024-27035', 'CVE-2024-27036', 'CVE-2024-27037', 'CVE-2024-27038', 'CVE-2024-27039', 'CVE-2024-27040', 'CVE-2024-27041', 'CVE-2024-27042', 'CVE-2024-27043', 'CVE-2024-27044', 'CVE-2024-27045', 'CVE-2024-27046', 'CVE-2024-27047', 'CVE-2024-27048', 'CVE-2024-27049', 'CVE-2024-27050', 'CVE-2024-27051', 'CVE-2024-27052', 'CVE-2024-27053', 'CVE-2024-27054', 'CVE-2024-27058', 'CVE-2024-27063', 'CVE-2024-27064', 'CVE-2024-27065', 'CVE-2024-27066', 'CVE-2024-27067', 'CVE-2024-27068', 'CVE-2024-27069', 'CVE-2024-27070', 'CVE-2024-27071', 'CVE-2024-27072', 'CVE-2024-27073', 'CVE-2024-27074', 'CVE-2024-27075', 'CVE-2024-27076', 'CVE-2024-27077', 'CVE-2024-27078', 'CVE-2024-27079', 'CVE-2024-27080', 'CVE-2024-27388', 'CVE-2024-27389', 'CVE-2024-27390', 'CVE-2024-27391', 'CVE-2024-27392', 'CVE-2024-27432', 'CVE-2024-27433', 'CVE-2024-27434', 'CVE-2024-27435', 'CVE-2024-27436', 'CVE-2024-27437', 'CVE-2024-35787', 'CVE-2024-35788', 'CVE-2024-35789', 'CVE-2024-35793', 'CVE-2024-35794', 'CVE-2024-35795', 'CVE-2024-35796', 'CVE-2024-35797', 'CVE-2024-35798', 'CVE-2024-35799', 'CVE-2024-35800', 'CVE-2024-35801', 'CVE-2024-35803', 'CVE-2024-35805', 'CVE-2024-35806', 'CVE-2024-35807', 'CVE-2024-35808', 'CVE-2024-35809', 'CVE-2024-35810', 'CVE-2024-35811', 'CVE-2024-35813', 'CVE-2024-35814', 'CVE-2024-35817', 'CVE-2024-35819', 'CVE-2024-35821', 'CVE-2024-35822', 'CVE-2024-35826', 'CVE-2024-35827', 'CVE-2024-35828', 'CVE-2024-35829', 'CVE-2024-35830', 'CVE-2024-35831', 'CVE-2024-35843', 'CVE-2024-35844', 'CVE-2024-35845', 'CVE-2024-35874');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6816-1');
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
