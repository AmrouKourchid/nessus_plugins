#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6828-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200372);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/02");

  script_cve_id(
    "CVE-2023-6270",
    "CVE-2023-7042",
    "CVE-2023-47233",
    "CVE-2023-52434",
    "CVE-2023-52435",
    "CVE-2023-52447",
    "CVE-2023-52486",
    "CVE-2023-52489",
    "CVE-2023-52491",
    "CVE-2023-52492",
    "CVE-2023-52493",
    "CVE-2023-52494",
    "CVE-2023-52497",
    "CVE-2023-52498",
    "CVE-2023-52530",
    "CVE-2023-52583",
    "CVE-2023-52587",
    "CVE-2023-52588",
    "CVE-2023-52594",
    "CVE-2023-52595",
    "CVE-2023-52597",
    "CVE-2023-52598",
    "CVE-2023-52599",
    "CVE-2023-52601",
    "CVE-2023-52602",
    "CVE-2023-52604",
    "CVE-2023-52606",
    "CVE-2023-52607",
    "CVE-2023-52608",
    "CVE-2023-52614",
    "CVE-2023-52615",
    "CVE-2023-52616",
    "CVE-2023-52617",
    "CVE-2023-52618",
    "CVE-2023-52619",
    "CVE-2023-52620",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2023-52627",
    "CVE-2023-52631",
    "CVE-2023-52633",
    "CVE-2023-52635",
    "CVE-2023-52637",
    "CVE-2023-52638",
    "CVE-2023-52640",
    "CVE-2023-52641",
    "CVE-2023-52642",
    "CVE-2023-52643",
    "CVE-2023-52644",
    "CVE-2023-52645",
    "CVE-2023-52650",
    "CVE-2023-52652",
    "CVE-2023-52656",
    "CVE-2023-52662",
    "CVE-2024-0841",
    "CVE-2024-1151",
    "CVE-2024-2201",
    "CVE-2024-22099",
    "CVE-2024-23849",
    "CVE-2024-26583",
    "CVE-2024-26584",
    "CVE-2024-26585",
    "CVE-2024-26592",
    "CVE-2024-26593",
    "CVE-2024-26594",
    "CVE-2024-26600",
    "CVE-2024-26601",
    "CVE-2024-26602",
    "CVE-2024-26603",
    "CVE-2024-26606",
    "CVE-2024-26608",
    "CVE-2024-26610",
    "CVE-2024-26614",
    "CVE-2024-26615",
    "CVE-2024-26622",
    "CVE-2024-26625",
    "CVE-2024-26627",
    "CVE-2024-26635",
    "CVE-2024-26636",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26644",
    "CVE-2024-26645",
    "CVE-2024-26651",
    "CVE-2024-26659",
    "CVE-2024-26660",
    "CVE-2024-26663",
    "CVE-2024-26664",
    "CVE-2024-26665",
    "CVE-2024-26668",
    "CVE-2024-26671",
    "CVE-2024-26673",
    "CVE-2024-26675",
    "CVE-2024-26676",
    "CVE-2024-26679",
    "CVE-2024-26684",
    "CVE-2024-26685",
    "CVE-2024-26688",
    "CVE-2024-26689",
    "CVE-2024-26695",
    "CVE-2024-26696",
    "CVE-2024-26697",
    "CVE-2024-26698",
    "CVE-2024-26702",
    "CVE-2024-26704",
    "CVE-2024-26707",
    "CVE-2024-26712",
    "CVE-2024-26715",
    "CVE-2024-26717",
    "CVE-2024-26720",
    "CVE-2024-26722",
    "CVE-2024-26733",
    "CVE-2024-26735",
    "CVE-2024-26736",
    "CVE-2024-26737",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26747",
    "CVE-2024-26748",
    "CVE-2024-26749",
    "CVE-2024-26750",
    "CVE-2024-26751",
    "CVE-2024-26752",
    "CVE-2024-26754",
    "CVE-2024-26763",
    "CVE-2024-26764",
    "CVE-2024-26766",
    "CVE-2024-26769",
    "CVE-2024-26771",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26774",
    "CVE-2024-26776",
    "CVE-2024-26777",
    "CVE-2024-26778",
    "CVE-2024-26779",
    "CVE-2024-26782",
    "CVE-2024-26787",
    "CVE-2024-26788",
    "CVE-2024-26790",
    "CVE-2024-26791",
    "CVE-2024-26792",
    "CVE-2024-26793",
    "CVE-2024-26795",
    "CVE-2024-26798",
    "CVE-2024-26801",
    "CVE-2024-26802",
    "CVE-2024-26803",
    "CVE-2024-26804",
    "CVE-2024-26805",
    "CVE-2024-26808",
    "CVE-2024-26809",
    "CVE-2024-26816",
    "CVE-2024-26820",
    "CVE-2024-26825",
    "CVE-2024-26826",
    "CVE-2024-26829",
    "CVE-2024-26833",
    "CVE-2024-26835",
    "CVE-2024-26838",
    "CVE-2024-26839",
    "CVE-2024-26840",
    "CVE-2024-26843",
    "CVE-2024-26845",
    "CVE-2024-26846",
    "CVE-2024-26851",
    "CVE-2024-26852",
    "CVE-2024-26855",
    "CVE-2024-26856",
    "CVE-2024-26857",
    "CVE-2024-26859",
    "CVE-2024-26861",
    "CVE-2024-26862",
    "CVE-2024-26863",
    "CVE-2024-26870",
    "CVE-2024-26872",
    "CVE-2024-26874",
    "CVE-2024-26875",
    "CVE-2024-26877",
    "CVE-2024-26878",
    "CVE-2024-26879",
    "CVE-2024-26880",
    "CVE-2024-26881",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26885",
    "CVE-2024-26889",
    "CVE-2024-26891",
    "CVE-2024-26894",
    "CVE-2024-26895",
    "CVE-2024-26897",
    "CVE-2024-26898",
    "CVE-2024-26901",
    "CVE-2024-26903",
    "CVE-2024-26906",
    "CVE-2024-26907",
    "CVE-2024-26910",
    "CVE-2024-26915",
    "CVE-2024-26916",
    "CVE-2024-26920",
    "CVE-2024-27024",
    "CVE-2024-27028",
    "CVE-2024-27030",
    "CVE-2024-27034",
    "CVE-2024-27037",
    "CVE-2024-27038",
    "CVE-2024-27039",
    "CVE-2024-27043",
    "CVE-2024-27044",
    "CVE-2024-27045",
    "CVE-2024-27046",
    "CVE-2024-27047",
    "CVE-2024-27051",
    "CVE-2024-27052",
    "CVE-2024-27053",
    "CVE-2024-27054",
    "CVE-2024-27065",
    "CVE-2024-27073",
    "CVE-2024-27074",
    "CVE-2024-27075",
    "CVE-2024-27076",
    "CVE-2024-27077",
    "CVE-2024-27078",
    "CVE-2024-27388",
    "CVE-2024-27390",
    "CVE-2024-27403",
    "CVE-2024-27405",
    "CVE-2024-27410",
    "CVE-2024-27412",
    "CVE-2024-27413",
    "CVE-2024-27414",
    "CVE-2024-27415",
    "CVE-2024-27416",
    "CVE-2024-27417",
    "CVE-2024-27419",
    "CVE-2024-27431",
    "CVE-2024-27432",
    "CVE-2024-27436",
    "CVE-2024-35811",
    "CVE-2024-35828",
    "CVE-2024-35829",
    "CVE-2024-35830",
    "CVE-2024-35844",
    "CVE-2024-35845"
  );
  script_xref(name:"USN", value:"6828-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (Intel IoTG) vulnerabilities (USN-6828-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6828-1 advisory.

    Zheng Wang discovered that the Broadcom FullMAC WLAN driver in the Linux kernel contained a race condition
    during device removal, leading to a use- after-free vulnerability. A physically proximate attacker could
    possibly use this to cause a denial of service (system crash). (CVE-2023-47233)

    It was discovered that the ATA over Ethernet (AoE) driver in the Linux kernel contained a race condition,
    leading to a use-after-free vulnerability. An attacker could use this to cause a denial of service or
    possibly execute arbitrary code. (CVE-2023-6270)

    It was discovered that the Atheros 802.11ac wireless driver did not properly validate certain data
    structures, leading to a NULL pointer dereference. An attacker could possibly use this to cause a denial
    of service. (CVE-2023-7042)

    It was discovered that the HugeTLB file system component of the Linux Kernel contained a NULL pointer
    dereference vulnerability. A privileged attacker could possibly use this to to cause a denial of service.
    (CVE-2024-0841)

    It was discovered that the Open vSwitch implementation in the Linux kernel could overflow its stack during
    recursive action operations under certain conditions. A local attacker could use this to cause a denial of
    service (system crash). (CVE-2024-1151)

    Sander Wiebing, Alvise de Faveri Tron, Herbert Bos, and Cristiano Giuffrida discovered that the Linux
    kernel mitigations for the initial Branch History Injection vulnerability (CVE-2022-0001) were
    insufficient for Intel processors. A local attacker could potentially use this to expose sensitive
    information. (CVE-2024-2201)

    Yuxuan Hu discovered that the Bluetooth RFCOMM protocol driver in the Linux Kernel contained a race
    condition, leading to a NULL pointer dereference. An attacker could possibly use this to cause a denial of
    service (system crash). (CVE-2024-22099)

    Chenyuan Yang discovered that the RDS Protocol implementation in the Linux kernel contained an out-of-
    bounds read vulnerability. An attacker could use this to possibly cause a denial of service (system
    crash). (CVE-2024-23849)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM32 architecture;

    - PowerPC architecture;

    - RISC-V architecture;

    - S390 architecture;

    - Core kernel;

    - x86 architecture;

    - Block layer subsystem;

    - ACPI drivers;

    - Android drivers;

    - Power management core;

    - Bus devices;

    - Hardware random number generator core;

    - Clock framework and drivers;

    - CPU frequency scaling framework;

    - Cryptographic API;

    - Device frequency scaling framework;

    - DMA engine subsystem;

    - ARM SCMI message protocol;

    - EFI core;

    - GPU drivers;

    - HID subsystem;

    - Hardware monitoring drivers;

    - I2C subsystem;

    - IIO ADC drivers;

    - IIO subsystem;

    - IIO Magnetometer sensors drivers;

    - InfiniBand drivers;

    - IOMMU subsystem;

    - Multiple devices driver;

    - Media drivers;

    - MMC subsystem;

    - Network drivers;

    - NTB driver;

    - NVME drivers;

    - PCI subsystem;

    - PCI driver for MicroSemi Switchtec;

    - PHY drivers;

    - MediaTek PM domains;

    - Power supply drivers;

    - SCSI drivers;

    - SPI subsystem;

    - Media staging drivers;

    - TCM subsystem;

    - USB subsystem;

    - DesignWare USB3 driver;

    - Framebuffer layer;

    - AFS file system;

    - File systems infrastructure;

    - BTRFS file system;

    - Ceph distributed file system;

    - EROFS file system;

    - Ext4 file system;

    - F2FS file system;

    - JFS file system;

    - Network file system client;

    - NILFS2 file system;

    - NTFS3 file system;

    - Pstore file system;

    - Diskquota system;

    - SMB network file system;

    - BPF subsystem;

    - Memory management;

    - Netfilter;

    - TLS protocol;

    - io_uring subsystem;

    - Bluetooth subsystem;

    - Ethernet bridge;

    - CAN network layer;

    - Networking core;

    - HSR network protocol;

    - IPv4 networking;

    - IPv6 networking;

    - L2TP protocol;

    - Logical Link layer;

    - MAC80211 subsystem;

    - Multipath TCP;

    - Netlink;

    - NET/ROM layer;

    - NFC subsystem;

    - Packet sockets;

    - RDS protocol;

    - SMC sockets;

    - Sun RPC protocol;

    - TIPC protocol;

    - Unix domain sockets;

    - Wireless networking;

    - Tomoyo security module;

    - Realtek audio codecs;

    - USB sound devices; (CVE-2024-26910, CVE-2024-27074, CVE-2023-52494, CVE-2023-52594, CVE-2024-26915,
    CVE-2024-26766, CVE-2023-52489, CVE-2024-35845, CVE-2024-26846, CVE-2024-26898, CVE-2024-26897,
    CVE-2024-26826, CVE-2024-26798, CVE-2023-52662, CVE-2024-26856, CVE-2023-52608, CVE-2024-26782,
    CVE-2024-27047, CVE-2024-27390, CVE-2024-26610, CVE-2024-26804, CVE-2023-52638, CVE-2024-26771,
    CVE-2024-26752, CVE-2024-26585, CVE-2024-26645, CVE-2024-26715, CVE-2024-27028, CVE-2024-26809,
    CVE-2024-26880, CVE-2024-27432, CVE-2024-27065, CVE-2024-26717, CVE-2023-52616, CVE-2024-26748,
    CVE-2024-26795, CVE-2024-26671, CVE-2024-26743, CVE-2024-27412, CVE-2024-26802, CVE-2024-26733,
    CVE-2024-26736, CVE-2023-52618, CVE-2024-27046, CVE-2024-26688, CVE-2024-26679, CVE-2024-26769,
    CVE-2024-27051, CVE-2024-26603, CVE-2024-26744, CVE-2023-52434, CVE-2024-26697, CVE-2024-27075,
    CVE-2023-52583, CVE-2024-26583, CVE-2024-27403, CVE-2024-26907, CVE-2024-26636, CVE-2024-27410,
    CVE-2023-52530, CVE-2024-26840, CVE-2024-26851, CVE-2024-26862, CVE-2023-52640, CVE-2024-35829,
    CVE-2024-26906, CVE-2024-26777, CVE-2024-27419, CVE-2024-26664, CVE-2024-26627, CVE-2024-26859,
    CVE-2023-52486, CVE-2023-52652, CVE-2024-26835, CVE-2024-35844, CVE-2024-26702, CVE-2024-26635,
    CVE-2024-26704, CVE-2023-52633, CVE-2024-26816, CVE-2024-26894, CVE-2024-26778, CVE-2023-52599,
    CVE-2024-35828, CVE-2024-26776, CVE-2023-52493, CVE-2024-26845, CVE-2024-26594, CVE-2024-26885,
    CVE-2024-26829, CVE-2023-52645, CVE-2024-26695, CVE-2023-52615, CVE-2024-26651, CVE-2024-26843,
    CVE-2023-52606, CVE-2024-26675, CVE-2024-26874, CVE-2024-26883, CVE-2024-26772, CVE-2024-26673,
    CVE-2024-26737, CVE-2023-52631, CVE-2024-26640, CVE-2023-52598, CVE-2024-26735, CVE-2024-26895,
    CVE-2024-26592, CVE-2023-52492, CVE-2024-26861, CVE-2023-52644, CVE-2024-26920, CVE-2024-26877,
    CVE-2024-26863, CVE-2024-26720, CVE-2024-26722, CVE-2024-27045, CVE-2024-27038, CVE-2024-26763,
    CVE-2024-26833, CVE-2024-27417, CVE-2024-26916, CVE-2024-26857, CVE-2024-26875, CVE-2024-26606,
    CVE-2024-27024, CVE-2024-26615, CVE-2023-52614, CVE-2023-52641, CVE-2024-26600, CVE-2024-27043,
    CVE-2023-52635, CVE-2024-26787, CVE-2024-26622, CVE-2024-27413, CVE-2024-26791, CVE-2023-52622,
    CVE-2023-52491, CVE-2023-52604, CVE-2024-27037, CVE-2024-26881, CVE-2024-26754, CVE-2024-26659,
    CVE-2024-26663, CVE-2024-26747, CVE-2023-52602, CVE-2024-26712, CVE-2024-26839, CVE-2024-26749,
    CVE-2024-26764, CVE-2024-26820, CVE-2024-26882, CVE-2024-27039, CVE-2024-27078, CVE-2024-26889,
    CVE-2024-26870, CVE-2024-26788, CVE-2024-26602, CVE-2024-26903, CVE-2024-27044, CVE-2024-27073,
    CVE-2023-52601, CVE-2023-52595, CVE-2024-26707, CVE-2024-27415, CVE-2023-52637, CVE-2024-26660,
    CVE-2024-27414, CVE-2024-27054, CVE-2023-52497, CVE-2024-26801, CVE-2023-52435, CVE-2023-52620,
    CVE-2023-52627, CVE-2024-26698, CVE-2023-52597, CVE-2024-27077, CVE-2023-52650, CVE-2024-26750,
    CVE-2024-26852, CVE-2024-27053, CVE-2023-52656, CVE-2024-26625, CVE-2024-26779, CVE-2024-27431,
    CVE-2024-26751, CVE-2024-26684, CVE-2024-26803, CVE-2024-26593, CVE-2023-52642, CVE-2023-52447,
    CVE-2024-26790, CVE-2024-26825, CVE-2024-26668, CVE-2023-52607, CVE-2024-26872, CVE-2024-27030,
    CVE-2023-52643, CVE-2024-26901, CVE-2024-35830, CVE-2024-26855, CVE-2023-52588, CVE-2023-52587,
    CVE-2024-26891, CVE-2024-26644, CVE-2024-26884, CVE-2024-26793, CVE-2024-26805, CVE-2024-26584,
    CVE-2024-27405, CVE-2023-52623, CVE-2024-26608, CVE-2024-26878, CVE-2024-27388, CVE-2024-27416,
    CVE-2024-26685, CVE-2024-27034, CVE-2024-26879, CVE-2024-26614, CVE-2024-26792, CVE-2023-52617,
    CVE-2024-26773, CVE-2024-26665, CVE-2024-26641, CVE-2023-52619, CVE-2024-35811, CVE-2024-27052,
    CVE-2024-27076, CVE-2024-26838, CVE-2024-26808, CVE-2024-26696, CVE-2024-26676, CVE-2024-26689,
    CVE-2024-26774, CVE-2024-26601, CVE-2023-52498, CVE-2024-27436)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6828-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1058-intel-iotg");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '20.04': {
    '5.15.0': {
      'intel-iotg': '5.15.0-1058'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6828-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-6270', 'CVE-2023-7042', 'CVE-2023-47233', 'CVE-2023-52434', 'CVE-2023-52435', 'CVE-2023-52447', 'CVE-2023-52486', 'CVE-2023-52489', 'CVE-2023-52491', 'CVE-2023-52492', 'CVE-2023-52493', 'CVE-2023-52494', 'CVE-2023-52497', 'CVE-2023-52498', 'CVE-2023-52530', 'CVE-2023-52583', 'CVE-2023-52587', 'CVE-2023-52588', 'CVE-2023-52594', 'CVE-2023-52595', 'CVE-2023-52597', 'CVE-2023-52598', 'CVE-2023-52599', 'CVE-2023-52601', 'CVE-2023-52602', 'CVE-2023-52604', 'CVE-2023-52606', 'CVE-2023-52607', 'CVE-2023-52608', 'CVE-2023-52614', 'CVE-2023-52615', 'CVE-2023-52616', 'CVE-2023-52617', 'CVE-2023-52618', 'CVE-2023-52619', 'CVE-2023-52620', 'CVE-2023-52622', 'CVE-2023-52623', 'CVE-2023-52627', 'CVE-2023-52631', 'CVE-2023-52633', 'CVE-2023-52635', 'CVE-2023-52637', 'CVE-2023-52638', 'CVE-2023-52640', 'CVE-2023-52641', 'CVE-2023-52642', 'CVE-2023-52643', 'CVE-2023-52644', 'CVE-2023-52645', 'CVE-2023-52650', 'CVE-2023-52652', 'CVE-2023-52656', 'CVE-2023-52662', 'CVE-2024-0841', 'CVE-2024-1151', 'CVE-2024-2201', 'CVE-2024-22099', 'CVE-2024-23849', 'CVE-2024-26583', 'CVE-2024-26584', 'CVE-2024-26585', 'CVE-2024-26592', 'CVE-2024-26593', 'CVE-2024-26594', 'CVE-2024-26600', 'CVE-2024-26601', 'CVE-2024-26602', 'CVE-2024-26603', 'CVE-2024-26606', 'CVE-2024-26608', 'CVE-2024-26610', 'CVE-2024-26614', 'CVE-2024-26615', 'CVE-2024-26622', 'CVE-2024-26625', 'CVE-2024-26627', 'CVE-2024-26635', 'CVE-2024-26636', 'CVE-2024-26640', 'CVE-2024-26641', 'CVE-2024-26644', 'CVE-2024-26645', 'CVE-2024-26651', 'CVE-2024-26659', 'CVE-2024-26660', 'CVE-2024-26663', 'CVE-2024-26664', 'CVE-2024-26665', 'CVE-2024-26668', 'CVE-2024-26671', 'CVE-2024-26673', 'CVE-2024-26675', 'CVE-2024-26676', 'CVE-2024-26679', 'CVE-2024-26684', 'CVE-2024-26685', 'CVE-2024-26688', 'CVE-2024-26689', 'CVE-2024-26695', 'CVE-2024-26696', 'CVE-2024-26697', 'CVE-2024-26698', 'CVE-2024-26702', 'CVE-2024-26704', 'CVE-2024-26707', 'CVE-2024-26712', 'CVE-2024-26715', 'CVE-2024-26717', 'CVE-2024-26720', 'CVE-2024-26722', 'CVE-2024-26733', 'CVE-2024-26735', 'CVE-2024-26736', 'CVE-2024-26737', 'CVE-2024-26743', 'CVE-2024-26744', 'CVE-2024-26747', 'CVE-2024-26748', 'CVE-2024-26749', 'CVE-2024-26750', 'CVE-2024-26751', 'CVE-2024-26752', 'CVE-2024-26754', 'CVE-2024-26763', 'CVE-2024-26764', 'CVE-2024-26766', 'CVE-2024-26769', 'CVE-2024-26771', 'CVE-2024-26772', 'CVE-2024-26773', 'CVE-2024-26774', 'CVE-2024-26776', 'CVE-2024-26777', 'CVE-2024-26778', 'CVE-2024-26779', 'CVE-2024-26782', 'CVE-2024-26787', 'CVE-2024-26788', 'CVE-2024-26790', 'CVE-2024-26791', 'CVE-2024-26792', 'CVE-2024-26793', 'CVE-2024-26795', 'CVE-2024-26798', 'CVE-2024-26801', 'CVE-2024-26802', 'CVE-2024-26803', 'CVE-2024-26804', 'CVE-2024-26805', 'CVE-2024-26808', 'CVE-2024-26809', 'CVE-2024-26816', 'CVE-2024-26820', 'CVE-2024-26825', 'CVE-2024-26826', 'CVE-2024-26829', 'CVE-2024-26833', 'CVE-2024-26835', 'CVE-2024-26838', 'CVE-2024-26839', 'CVE-2024-26840', 'CVE-2024-26843', 'CVE-2024-26845', 'CVE-2024-26846', 'CVE-2024-26851', 'CVE-2024-26852', 'CVE-2024-26855', 'CVE-2024-26856', 'CVE-2024-26857', 'CVE-2024-26859', 'CVE-2024-26861', 'CVE-2024-26862', 'CVE-2024-26863', 'CVE-2024-26870', 'CVE-2024-26872', 'CVE-2024-26874', 'CVE-2024-26875', 'CVE-2024-26877', 'CVE-2024-26878', 'CVE-2024-26879', 'CVE-2024-26880', 'CVE-2024-26881', 'CVE-2024-26882', 'CVE-2024-26883', 'CVE-2024-26884', 'CVE-2024-26885', 'CVE-2024-26889', 'CVE-2024-26891', 'CVE-2024-26894', 'CVE-2024-26895', 'CVE-2024-26897', 'CVE-2024-26898', 'CVE-2024-26901', 'CVE-2024-26903', 'CVE-2024-26906', 'CVE-2024-26907', 'CVE-2024-26910', 'CVE-2024-26915', 'CVE-2024-26916', 'CVE-2024-26920', 'CVE-2024-27024', 'CVE-2024-27028', 'CVE-2024-27030', 'CVE-2024-27034', 'CVE-2024-27037', 'CVE-2024-27038', 'CVE-2024-27039', 'CVE-2024-27043', 'CVE-2024-27044', 'CVE-2024-27045', 'CVE-2024-27046', 'CVE-2024-27047', 'CVE-2024-27051', 'CVE-2024-27052', 'CVE-2024-27053', 'CVE-2024-27054', 'CVE-2024-27065', 'CVE-2024-27073', 'CVE-2024-27074', 'CVE-2024-27075', 'CVE-2024-27076', 'CVE-2024-27077', 'CVE-2024-27078', 'CVE-2024-27388', 'CVE-2024-27390', 'CVE-2024-27403', 'CVE-2024-27405', 'CVE-2024-27410', 'CVE-2024-27412', 'CVE-2024-27413', 'CVE-2024-27414', 'CVE-2024-27415', 'CVE-2024-27416', 'CVE-2024-27417', 'CVE-2024-27419', 'CVE-2024-27431', 'CVE-2024-27432', 'CVE-2024-27436', 'CVE-2024-35811', 'CVE-2024-35828', 'CVE-2024-35829', 'CVE-2024-35830', 'CVE-2024-35844', 'CVE-2024-35845');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6828-1');
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
