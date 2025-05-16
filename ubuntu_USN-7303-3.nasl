#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7303-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(217186);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id(
    "CVE-2023-52917",
    "CVE-2024-41016",
    "CVE-2024-47670",
    "CVE-2024-47671",
    "CVE-2024-47672",
    "CVE-2024-47673",
    "CVE-2024-47675",
    "CVE-2024-47677",
    "CVE-2024-47678",
    "CVE-2024-47679",
    "CVE-2024-47681",
    "CVE-2024-47682",
    "CVE-2024-47684",
    "CVE-2024-47685",
    "CVE-2024-47686",
    "CVE-2024-47687",
    "CVE-2024-47688",
    "CVE-2024-47689",
    "CVE-2024-47690",
    "CVE-2024-47691",
    "CVE-2024-47692",
    "CVE-2024-47693",
    "CVE-2024-47695",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47698",
    "CVE-2024-47699",
    "CVE-2024-47700",
    "CVE-2024-47701",
    "CVE-2024-47702",
    "CVE-2024-47703",
    "CVE-2024-47704",
    "CVE-2024-47705",
    "CVE-2024-47706",
    "CVE-2024-47707",
    "CVE-2024-47709",
    "CVE-2024-47710",
    "CVE-2024-47712",
    "CVE-2024-47713",
    "CVE-2024-47714",
    "CVE-2024-47715",
    "CVE-2024-47716",
    "CVE-2024-47718",
    "CVE-2024-47719",
    "CVE-2024-47720",
    "CVE-2024-47723",
    "CVE-2024-47727",
    "CVE-2024-47728",
    "CVE-2024-47730",
    "CVE-2024-47731",
    "CVE-2024-47732",
    "CVE-2024-47733",
    "CVE-2024-47734",
    "CVE-2024-47735",
    "CVE-2024-47737",
    "CVE-2024-47738",
    "CVE-2024-47739",
    "CVE-2024-47740",
    "CVE-2024-47741",
    "CVE-2024-47742",
    "CVE-2024-47743",
    "CVE-2024-47744",
    "CVE-2024-47745",
    "CVE-2024-47747",
    "CVE-2024-47748",
    "CVE-2024-47749",
    "CVE-2024-47750",
    "CVE-2024-47751",
    "CVE-2024-47752",
    "CVE-2024-47753",
    "CVE-2024-47754",
    "CVE-2024-47756",
    "CVE-2024-47757",
    "CVE-2024-49850",
    "CVE-2024-49851",
    "CVE-2024-49852",
    "CVE-2024-49853",
    "CVE-2024-49855",
    "CVE-2024-49856",
    "CVE-2024-49858",
    "CVE-2024-49859",
    "CVE-2024-49860",
    "CVE-2024-49861",
    "CVE-2024-49862",
    "CVE-2024-49863",
    "CVE-2024-49864",
    "CVE-2024-49866",
    "CVE-2024-49867",
    "CVE-2024-49868",
    "CVE-2024-49870",
    "CVE-2024-49871",
    "CVE-2024-49874",
    "CVE-2024-49875",
    "CVE-2024-49876",
    "CVE-2024-49877",
    "CVE-2024-49878",
    "CVE-2024-49879",
    "CVE-2024-49880",
    "CVE-2024-49881",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49884",
    "CVE-2024-49885",
    "CVE-2024-49886",
    "CVE-2024-49888",
    "CVE-2024-49889",
    "CVE-2024-49890",
    "CVE-2024-49891",
    "CVE-2024-49892",
    "CVE-2024-49894",
    "CVE-2024-49895",
    "CVE-2024-49896",
    "CVE-2024-49897",
    "CVE-2024-49898",
    "CVE-2024-49900",
    "CVE-2024-49901",
    "CVE-2024-49902",
    "CVE-2024-49903",
    "CVE-2024-49905",
    "CVE-2024-49907",
    "CVE-2024-49909",
    "CVE-2024-49911",
    "CVE-2024-49912",
    "CVE-2024-49913",
    "CVE-2024-49915",
    "CVE-2024-49917",
    "CVE-2024-49918",
    "CVE-2024-49919",
    "CVE-2024-49922",
    "CVE-2024-49923",
    "CVE-2024-49924",
    "CVE-2024-49925",
    "CVE-2024-49926",
    "CVE-2024-49927",
    "CVE-2024-49928",
    "CVE-2024-49929",
    "CVE-2024-49930",
    "CVE-2024-49931",
    "CVE-2024-49933",
    "CVE-2024-49934",
    "CVE-2024-49935",
    "CVE-2024-49936",
    "CVE-2024-49937",
    "CVE-2024-49938",
    "CVE-2024-49939",
    "CVE-2024-49942",
    "CVE-2024-49944",
    "CVE-2024-49945",
    "CVE-2024-49946",
    "CVE-2024-49947",
    "CVE-2024-49948",
    "CVE-2024-49949",
    "CVE-2024-49950",
    "CVE-2024-49951",
    "CVE-2024-49952",
    "CVE-2024-49953",
    "CVE-2024-49954",
    "CVE-2024-49955",
    "CVE-2024-49957",
    "CVE-2024-49958",
    "CVE-2024-49959",
    "CVE-2024-49960",
    "CVE-2024-49961",
    "CVE-2024-49962",
    "CVE-2024-49963",
    "CVE-2024-49965",
    "CVE-2024-49966",
    "CVE-2024-49969",
    "CVE-2024-49973",
    "CVE-2024-49974",
    "CVE-2024-49975",
    "CVE-2024-49976",
    "CVE-2024-49977",
    "CVE-2024-49978",
    "CVE-2024-49980",
    "CVE-2024-49981",
    "CVE-2024-49982",
    "CVE-2024-49983",
    "CVE-2024-49985",
    "CVE-2024-49986",
    "CVE-2024-49987",
    "CVE-2024-49988",
    "CVE-2024-49989",
    "CVE-2024-49991",
    "CVE-2024-49992",
    "CVE-2024-49994",
    "CVE-2024-49995",
    "CVE-2024-49996",
    "CVE-2024-49997",
    "CVE-2024-49998",
    "CVE-2024-49999",
    "CVE-2024-50000",
    "CVE-2024-50001",
    "CVE-2024-50002",
    "CVE-2024-50005",
    "CVE-2024-50006",
    "CVE-2024-50007",
    "CVE-2024-50008",
    "CVE-2024-50012",
    "CVE-2024-50013",
    "CVE-2024-50014",
    "CVE-2024-50015",
    "CVE-2024-50016",
    "CVE-2024-50017",
    "CVE-2024-50175",
    "CVE-2024-50176",
    "CVE-2024-50179",
    "CVE-2024-53144"
  );
  script_xref(name:"USN", value:"7303-3");

  script_name(english:"Ubuntu 22.04 LTS / 24.04 LTS : Linux kernel vulnerabilities (USN-7303-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 24.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-7303-3 advisory.

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM32 architecture;

    - x86 architecture;

    - Block layer subsystem;

    - Cryptographic API;

    - ACPI drivers;

    - Drivers core;

    - ATA over ethernet (AOE) driver;

    - Network block device driver;

    - TPM device driver;

    - Hardware crypto device drivers;

    - ARM SCMI message protocol;

    - EFI core;

    - GPU drivers;

    - I2C subsystem;

    - I3C subsystem;

    - InfiniBand drivers;

    - Input Device core drivers;

    - IOMMU subsystem;

    - Mailbox framework;

    - Media drivers;

    - Ethernet bonding driver;

    - Network drivers;

    - Mellanox network drivers;

    - STMicroelectronics network drivers;

    - NTB driver;

    - PCI subsystem;

    - Alibaba DDR Sub-System Driveway PMU driver;

    - x86 platform drivers;

    - Powercap sysfs driver;

    - Remote Processor subsystem;

    - SCSI subsystem;

    - USB Device Class drivers;

    - vDPA drivers;

    - Virtio Host (VHOST) subsystem;

    - Framebuffer layer;

    - AFS file system;

    - BTRFS file system;

    - File systems infrastructure;

    - Ceph distributed file system;

    - Ext4 file system;

    - F2FS file system;

    - JFS file system;

    - Network file systems library;

    - Network file system (NFS) server daemon;

    - NILFS2 file system;

    - SMB network file system;

    - BPF subsystem;

    - Virtio network driver;

    - TCP network protocol;

    - Perf events;

    - Padata parallel execution mechanism;

    - RCU subsystem;

    - Arbitrary resource management;

    - Static call mechanism;

    - Tracing infrastructure;

    - Memory management;

    - Bluetooth subsystem;

    - CAN network layer;

    - Networking core;

    - Distributed Switch Architecture;

    - IPv4 networking;

    - IPv6 networking;

    - MAC80211 subsystem;

    - IEEE 802.15.4 subsystem;

    - NCSI (Network Controller Sideband Interface) driver;

    - RxRPC session sockets;

    - SCTP protocol;

    - TIPC protocol;

    - Wireless networking;

    - AudioScience HPI driver;

    - KVM core; (CVE-2024-47709, CVE-2024-49889, CVE-2024-49931, CVE-2024-50008, CVE-2024-49969,
    CVE-2024-49975, CVE-2024-49958, CVE-2024-47756, CVE-2024-49944, CVE-2024-47707, CVE-2024-47693,
    CVE-2024-47686, CVE-2024-47734, CVE-2024-47750, CVE-2024-50179, CVE-2024-49942, CVE-2024-49864,
    CVE-2024-49891, CVE-2024-49965, CVE-2024-49905, CVE-2024-47719, CVE-2024-49877, CVE-2024-47688,
    CVE-2024-47691, CVE-2024-47710, CVE-2024-47748, CVE-2024-49948, CVE-2024-49998, CVE-2024-47673,
    CVE-2024-47738, CVE-2024-47701, CVE-2024-47705, CVE-2024-49930, CVE-2024-49985, CVE-2024-50016,
    CVE-2024-53144, CVE-2023-52917, CVE-2024-47690, CVE-2024-47675, CVE-2024-50176, CVE-2024-49922,
    CVE-2024-47704, CVE-2024-49982, CVE-2024-47741, CVE-2024-49991, CVE-2024-49902, CVE-2024-49883,
    CVE-2024-49892, CVE-2024-50002, CVE-2024-49945, CVE-2024-49959, CVE-2024-47732, CVE-2024-49856,
    CVE-2024-47677, CVE-2024-49978, CVE-2024-49966, CVE-2024-49937, CVE-2024-47744, CVE-2024-49890,
    CVE-2024-47739, CVE-2024-50012, CVE-2024-47742, CVE-2024-49980, CVE-2024-47706, CVE-2024-49994,
    CVE-2024-50017, CVE-2024-47697, CVE-2024-49996, CVE-2024-49953, CVE-2024-49871, CVE-2024-47723,
    CVE-2024-49987, CVE-2024-49917, CVE-2024-49888, CVE-2024-49866, CVE-2024-50005, CVE-2024-47681,
    CVE-2024-49870, CVE-2024-49898, CVE-2024-49981, CVE-2024-49947, CVE-2024-49918, CVE-2024-49983,
    CVE-2024-47698, CVE-2024-49850, CVE-2024-50007, CVE-2024-49900, CVE-2024-49923, CVE-2024-49909,
    CVE-2024-47687, CVE-2024-50015, CVE-2024-47715, CVE-2024-47745, CVE-2024-49926, CVE-2024-49879,
    CVE-2024-49986, CVE-2024-49929, CVE-2024-49949, CVE-2024-49976, CVE-2024-47749, CVE-2024-47689,
    CVE-2024-47720, CVE-2024-47743, CVE-2024-49878, CVE-2024-49935, CVE-2024-49955, CVE-2024-49997,
    CVE-2024-49860, CVE-2024-47703, CVE-2024-50175, CVE-2024-49855, CVE-2024-49861, CVE-2024-49951,
    CVE-2024-49863, CVE-2024-49882, CVE-2024-50000, CVE-2024-49912, CVE-2024-49974, CVE-2024-49977,
    CVE-2024-47752, CVE-2024-47700, CVE-2024-49911, CVE-2024-49852, CVE-2024-47740, CVE-2024-47671,
    CVE-2024-49988, CVE-2024-47699, CVE-2024-47757, CVE-2024-49933, CVE-2024-49913, CVE-2024-49907,
    CVE-2024-49881, CVE-2024-47751, CVE-2024-47753, CVE-2024-47731, CVE-2024-47730, CVE-2024-49934,
    CVE-2024-49957, CVE-2024-49938, CVE-2024-47728, CVE-2024-49867, CVE-2024-47754, CVE-2024-49919,
    CVE-2024-49992, CVE-2024-49950, CVE-2024-49954, CVE-2024-49924, CVE-2024-47670, CVE-2024-50014,
    CVE-2024-47684, CVE-2024-49884, CVE-2024-47678, CVE-2024-49894, CVE-2024-49859, CVE-2024-47735,
    CVE-2024-47696, CVE-2024-49999, CVE-2024-49880, CVE-2024-47747, CVE-2024-49885, CVE-2024-49963,
    CVE-2024-49995, CVE-2024-49897, CVE-2024-49868, CVE-2024-49862, CVE-2024-49928, CVE-2024-47685,
    CVE-2024-47692, CVE-2024-49927, CVE-2024-47695, CVE-2024-49896, CVE-2024-49875, CVE-2024-49853,
    CVE-2024-47714, CVE-2024-49989, CVE-2024-49858, CVE-2024-49952, CVE-2024-49973, CVE-2024-49925,
    CVE-2024-49851, CVE-2024-47712, CVE-2024-49961, CVE-2024-47713, CVE-2024-47718, CVE-2024-49962,
    CVE-2024-47737, CVE-2024-50001, CVE-2024-49876, CVE-2024-49903, CVE-2024-49939, CVE-2024-49886,
    CVE-2024-47679, CVE-2024-50006, CVE-2024-49874, CVE-2024-47716, CVE-2024-49895, CVE-2024-47727,
    CVE-2024-47672, CVE-2024-49901, CVE-2024-47733, CVE-2024-47682, CVE-2024-47702, CVE-2024-50013,
    CVE-2024-41016, CVE-2024-49960, CVE-2024-49936, CVE-2024-49946, CVE-2024-49915)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7303-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1019-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1024-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1024-gcp-64k");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('22.04' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '22.04': {
    '6.8.0': {
      'gcp': '6.8.0-1024',
      'gcp-64k': '6.8.0-1024'
    }
  },
  '24.04': {
    '6.8.0': {
      'raspi': '6.8.0-1019'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7303-3');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-52917', 'CVE-2024-41016', 'CVE-2024-47670', 'CVE-2024-47671', 'CVE-2024-47672', 'CVE-2024-47673', 'CVE-2024-47675', 'CVE-2024-47677', 'CVE-2024-47678', 'CVE-2024-47679', 'CVE-2024-47681', 'CVE-2024-47682', 'CVE-2024-47684', 'CVE-2024-47685', 'CVE-2024-47686', 'CVE-2024-47687', 'CVE-2024-47688', 'CVE-2024-47689', 'CVE-2024-47690', 'CVE-2024-47691', 'CVE-2024-47692', 'CVE-2024-47693', 'CVE-2024-47695', 'CVE-2024-47696', 'CVE-2024-47697', 'CVE-2024-47698', 'CVE-2024-47699', 'CVE-2024-47700', 'CVE-2024-47701', 'CVE-2024-47702', 'CVE-2024-47703', 'CVE-2024-47704', 'CVE-2024-47705', 'CVE-2024-47706', 'CVE-2024-47707', 'CVE-2024-47709', 'CVE-2024-47710', 'CVE-2024-47712', 'CVE-2024-47713', 'CVE-2024-47714', 'CVE-2024-47715', 'CVE-2024-47716', 'CVE-2024-47718', 'CVE-2024-47719', 'CVE-2024-47720', 'CVE-2024-47723', 'CVE-2024-47727', 'CVE-2024-47728', 'CVE-2024-47730', 'CVE-2024-47731', 'CVE-2024-47732', 'CVE-2024-47733', 'CVE-2024-47734', 'CVE-2024-47735', 'CVE-2024-47737', 'CVE-2024-47738', 'CVE-2024-47739', 'CVE-2024-47740', 'CVE-2024-47741', 'CVE-2024-47742', 'CVE-2024-47743', 'CVE-2024-47744', 'CVE-2024-47745', 'CVE-2024-47747', 'CVE-2024-47748', 'CVE-2024-47749', 'CVE-2024-47750', 'CVE-2024-47751', 'CVE-2024-47752', 'CVE-2024-47753', 'CVE-2024-47754', 'CVE-2024-47756', 'CVE-2024-47757', 'CVE-2024-49850', 'CVE-2024-49851', 'CVE-2024-49852', 'CVE-2024-49853', 'CVE-2024-49855', 'CVE-2024-49856', 'CVE-2024-49858', 'CVE-2024-49859', 'CVE-2024-49860', 'CVE-2024-49861', 'CVE-2024-49862', 'CVE-2024-49863', 'CVE-2024-49864', 'CVE-2024-49866', 'CVE-2024-49867', 'CVE-2024-49868', 'CVE-2024-49870', 'CVE-2024-49871', 'CVE-2024-49874', 'CVE-2024-49875', 'CVE-2024-49876', 'CVE-2024-49877', 'CVE-2024-49878', 'CVE-2024-49879', 'CVE-2024-49880', 'CVE-2024-49881', 'CVE-2024-49882', 'CVE-2024-49883', 'CVE-2024-49884', 'CVE-2024-49885', 'CVE-2024-49886', 'CVE-2024-49888', 'CVE-2024-49889', 'CVE-2024-49890', 'CVE-2024-49891', 'CVE-2024-49892', 'CVE-2024-49894', 'CVE-2024-49895', 'CVE-2024-49896', 'CVE-2024-49897', 'CVE-2024-49898', 'CVE-2024-49900', 'CVE-2024-49901', 'CVE-2024-49902', 'CVE-2024-49903', 'CVE-2024-49905', 'CVE-2024-49907', 'CVE-2024-49909', 'CVE-2024-49911', 'CVE-2024-49912', 'CVE-2024-49913', 'CVE-2024-49915', 'CVE-2024-49917', 'CVE-2024-49918', 'CVE-2024-49919', 'CVE-2024-49922', 'CVE-2024-49923', 'CVE-2024-49924', 'CVE-2024-49925', 'CVE-2024-49926', 'CVE-2024-49927', 'CVE-2024-49928', 'CVE-2024-49929', 'CVE-2024-49930', 'CVE-2024-49931', 'CVE-2024-49933', 'CVE-2024-49934', 'CVE-2024-49935', 'CVE-2024-49936', 'CVE-2024-49937', 'CVE-2024-49938', 'CVE-2024-49939', 'CVE-2024-49942', 'CVE-2024-49944', 'CVE-2024-49945', 'CVE-2024-49946', 'CVE-2024-49947', 'CVE-2024-49948', 'CVE-2024-49949', 'CVE-2024-49950', 'CVE-2024-49951', 'CVE-2024-49952', 'CVE-2024-49953', 'CVE-2024-49954', 'CVE-2024-49955', 'CVE-2024-49957', 'CVE-2024-49958', 'CVE-2024-49959', 'CVE-2024-49960', 'CVE-2024-49961', 'CVE-2024-49962', 'CVE-2024-49963', 'CVE-2024-49965', 'CVE-2024-49966', 'CVE-2024-49969', 'CVE-2024-49973', 'CVE-2024-49974', 'CVE-2024-49975', 'CVE-2024-49976', 'CVE-2024-49977', 'CVE-2024-49978', 'CVE-2024-49980', 'CVE-2024-49981', 'CVE-2024-49982', 'CVE-2024-49983', 'CVE-2024-49985', 'CVE-2024-49986', 'CVE-2024-49987', 'CVE-2024-49988', 'CVE-2024-49989', 'CVE-2024-49991', 'CVE-2024-49992', 'CVE-2024-49994', 'CVE-2024-49995', 'CVE-2024-49996', 'CVE-2024-49997', 'CVE-2024-49998', 'CVE-2024-49999', 'CVE-2024-50000', 'CVE-2024-50001', 'CVE-2024-50002', 'CVE-2024-50005', 'CVE-2024-50006', 'CVE-2024-50007', 'CVE-2024-50008', 'CVE-2024-50012', 'CVE-2024-50013', 'CVE-2024-50014', 'CVE-2024-50015', 'CVE-2024-50016', 'CVE-2024-50017', 'CVE-2024-50175', 'CVE-2024-50176', 'CVE-2024-50179', 'CVE-2024-53144');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7303-3');
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
