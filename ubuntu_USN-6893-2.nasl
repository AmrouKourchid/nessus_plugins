#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6893-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202476);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/15");

  script_cve_id(
    "CVE-2023-52699",
    "CVE-2024-24857",
    "CVE-2024-24858",
    "CVE-2024-24859",
    "CVE-2024-26811",
    "CVE-2024-26817",
    "CVE-2024-26921",
    "CVE-2024-26922",
    "CVE-2024-26923",
    "CVE-2024-26925",
    "CVE-2024-26926",
    "CVE-2024-26928",
    "CVE-2024-26936",
    "CVE-2024-26980",
    "CVE-2024-26981",
    "CVE-2024-26982",
    "CVE-2024-26983",
    "CVE-2024-26984",
    "CVE-2024-26985",
    "CVE-2024-26986",
    "CVE-2024-26987",
    "CVE-2024-26988",
    "CVE-2024-26989",
    "CVE-2024-26990",
    "CVE-2024-26991",
    "CVE-2024-26992",
    "CVE-2024-26993",
    "CVE-2024-26994",
    "CVE-2024-26995",
    "CVE-2024-26996",
    "CVE-2024-26997",
    "CVE-2024-26998",
    "CVE-2024-26999",
    "CVE-2024-27000",
    "CVE-2024-27001",
    "CVE-2024-27002",
    "CVE-2024-27003",
    "CVE-2024-27004",
    "CVE-2024-27005",
    "CVE-2024-27006",
    "CVE-2024-27007",
    "CVE-2024-27008",
    "CVE-2024-27009",
    "CVE-2024-27010",
    "CVE-2024-27011",
    "CVE-2024-27012",
    "CVE-2024-27013",
    "CVE-2024-27014",
    "CVE-2024-27015",
    "CVE-2024-27016",
    "CVE-2024-27017",
    "CVE-2024-27018",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27021",
    "CVE-2024-27022",
    "CVE-2024-35860",
    "CVE-2024-35861",
    "CVE-2024-35862",
    "CVE-2024-35863",
    "CVE-2024-35864",
    "CVE-2024-35865",
    "CVE-2024-35866",
    "CVE-2024-35867",
    "CVE-2024-35868",
    "CVE-2024-35869",
    "CVE-2024-35870",
    "CVE-2024-35871",
    "CVE-2024-35872",
    "CVE-2024-35873",
    "CVE-2024-35875",
    "CVE-2024-35877",
    "CVE-2024-35878",
    "CVE-2024-35879",
    "CVE-2024-35880",
    "CVE-2024-35882",
    "CVE-2024-35883",
    "CVE-2024-35884",
    "CVE-2024-35885",
    "CVE-2024-35886",
    "CVE-2024-35887",
    "CVE-2024-35888",
    "CVE-2024-35889",
    "CVE-2024-35890",
    "CVE-2024-35891",
    "CVE-2024-35892",
    "CVE-2024-35893",
    "CVE-2024-35894",
    "CVE-2024-35895",
    "CVE-2024-35896",
    "CVE-2024-35897",
    "CVE-2024-35898",
    "CVE-2024-35899",
    "CVE-2024-35900",
    "CVE-2024-35901",
    "CVE-2024-35902",
    "CVE-2024-35903",
    "CVE-2024-35904",
    "CVE-2024-35905",
    "CVE-2024-35907",
    "CVE-2024-35908",
    "CVE-2024-35909",
    "CVE-2024-35910",
    "CVE-2024-35911",
    "CVE-2024-35912",
    "CVE-2024-35913",
    "CVE-2024-35914",
    "CVE-2024-35915",
    "CVE-2024-35916",
    "CVE-2024-35917",
    "CVE-2024-35918",
    "CVE-2024-35919",
    "CVE-2024-35920",
    "CVE-2024-35921",
    "CVE-2024-35922",
    "CVE-2024-35924",
    "CVE-2024-35925",
    "CVE-2024-35926",
    "CVE-2024-35927",
    "CVE-2024-35929",
    "CVE-2024-35930",
    "CVE-2024-35931",
    "CVE-2024-35932",
    "CVE-2024-35933",
    "CVE-2024-35934",
    "CVE-2024-35935",
    "CVE-2024-35936",
    "CVE-2024-35937",
    "CVE-2024-35938",
    "CVE-2024-35939",
    "CVE-2024-35940",
    "CVE-2024-35942",
    "CVE-2024-35943",
    "CVE-2024-35944",
    "CVE-2024-35945",
    "CVE-2024-35946",
    "CVE-2024-35950",
    "CVE-2024-35951",
    "CVE-2024-35952",
    "CVE-2024-35953",
    "CVE-2024-35954",
    "CVE-2024-35955",
    "CVE-2024-35956",
    "CVE-2024-35957",
    "CVE-2024-35958",
    "CVE-2024-35959",
    "CVE-2024-35960",
    "CVE-2024-35961",
    "CVE-2024-35963",
    "CVE-2024-35964",
    "CVE-2024-35965",
    "CVE-2024-35966",
    "CVE-2024-35967",
    "CVE-2024-35968",
    "CVE-2024-35969",
    "CVE-2024-35970",
    "CVE-2024-35971",
    "CVE-2024-35972",
    "CVE-2024-35973",
    "CVE-2024-35974",
    "CVE-2024-35975",
    "CVE-2024-35976",
    "CVE-2024-35977",
    "CVE-2024-35978",
    "CVE-2024-35979",
    "CVE-2024-35980",
    "CVE-2024-35981",
    "CVE-2024-35982",
    "CVE-2024-35985",
    "CVE-2024-36018",
    "CVE-2024-36019",
    "CVE-2024-36020",
    "CVE-2024-36021",
    "CVE-2024-36022",
    "CVE-2024-36023",
    "CVE-2024-36024",
    "CVE-2024-36025",
    "CVE-2024-36026",
    "CVE-2024-36027"
  );
  script_xref(name:"USN", value:"6893-2");

  script_name(english:"Ubuntu 24.04 LTS : Linux kernel vulnerabilities (USN-6893-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 24.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6893-2 advisory.

    It was discovered that a race condition existed in the Bluetooth subsystem in the Linux kernel when
    modifying certain settings values through debugfs. A privileged local attacker could use this to cause a
    denial of service.

    (CVE-2024-24857, CVE-2024-24858, CVE-2024-24859)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - RISC-V architecture;

    - S390 architecture;

    - x86 architecture;

    - Block layer subsystem;

    - Compute Acceleration Framework;

    - Accessibility subsystem;

    - Android drivers;

    - Drivers core;

    - Bluetooth drivers;

    - Clock framework and drivers;

    - Data acquisition framework and drivers;

    - Cryptographic API;

    - Buffer Sharing and Synchronization framework;

    - GPU drivers;

    - On-Chip Interconnect management framework;

    - IOMMU subsystem;

    - Multiple devices driver;

    - Media drivers;

    - VMware VMCI Driver;

    - Network drivers;

    - Microsoft Azure Network Adapter (MANA) driver;

    - Device tree and open firmware driver;

    - Chrome hardware platform drivers;

    - i.MX PM domains;

    - TI SCI PM domains driver;

    - S/390 drivers;

    - SCSI drivers;

    - SPI subsystem;

    - Thermal drivers;

    - TTY drivers;

    - USB subsystem;

    - Framebuffer layer;

    - BTRFS file system;

    - Network file system server daemon;

    - NILFS2 file system;

    - File systems infrastructure;

    - Pstore file system;

    - SMB network file system;

    - BPF subsystem;

    - Bluetooth subsystem;

    - Netfilter;

    - io_uring subsystem;

    - Core kernel;

    - Extra boot config (XBC);

    - Memory management;

    - Amateur Radio drivers;

    - B.A.T.M.A.N. meshing protocol;

    - Ethernet bridge;

    - Networking core;

    - IPv4 networking;

    - IPv6 networking;

    - Multipath TCP;

    - NFC subsystem;

    - RDS protocol;

    - Network traffic control;

    - SMC sockets;

    - Sun RPC protocol;

    - TLS protocol;

    - Unix domain sockets;

    - Wireless networking;

    - eXpress Data Path;

    - SELinux security module; (CVE-2024-35976, CVE-2024-35873, CVE-2024-35959, CVE-2024-27012,
    CVE-2024-36025, CVE-2024-35868, CVE-2024-26995, CVE-2024-35916, CVE-2024-36023, CVE-2024-35964,
    CVE-2024-35890, CVE-2024-26980, CVE-2024-35950, CVE-2024-27006, CVE-2024-35955, CVE-2024-35885,
    CVE-2024-35960, CVE-2024-35932, CVE-2024-26986, CVE-2024-35884, CVE-2024-35860, CVE-2024-36020,
    CVE-2024-35930, CVE-2024-35919, CVE-2024-27020, CVE-2024-26928, CVE-2024-35903, CVE-2024-35907,
    CVE-2024-35904, CVE-2024-35972, CVE-2024-35892, CVE-2024-26921, CVE-2024-35869, CVE-2024-35957,
    CVE-2024-35967, CVE-2024-35927, CVE-2024-35946, CVE-2024-27000, CVE-2024-35943, CVE-2024-35902,
    CVE-2024-27013, CVE-2024-35968, CVE-2024-35970, CVE-2024-35865, CVE-2024-36022, CVE-2024-26993,
    CVE-2024-36027, CVE-2024-35895, CVE-2024-35908, CVE-2024-35901, CVE-2024-35872, CVE-2024-26925,
    CVE-2024-35917, CVE-2024-35898, CVE-2024-35861, CVE-2024-35900, CVE-2024-26984, CVE-2024-35891,
    CVE-2023-52699, CVE-2024-35961, CVE-2024-35951, CVE-2024-36019, CVE-2024-27021, CVE-2024-35939,
    CVE-2024-26997, CVE-2024-26999, CVE-2024-35897, CVE-2024-35896, CVE-2024-26817, CVE-2024-35875,
    CVE-2024-35935, CVE-2024-27015, CVE-2024-26982, CVE-2024-35958, CVE-2024-26989, CVE-2024-26922,
    CVE-2024-26811, CVE-2024-27003, CVE-2024-35920, CVE-2024-27007, CVE-2024-35879, CVE-2024-35979,
    CVE-2024-35978, CVE-2024-35914, CVE-2024-35938, CVE-2024-35913, CVE-2024-26985, CVE-2024-35915,
    CVE-2024-35974, CVE-2024-27001, CVE-2024-35940, CVE-2024-35867, CVE-2024-26994, CVE-2024-35886,
    CVE-2024-35899, CVE-2024-27022, CVE-2024-35910, CVE-2024-35893, CVE-2024-27010, CVE-2024-36024,
    CVE-2024-26926, CVE-2024-26923, CVE-2024-26990, CVE-2024-35912, CVE-2024-26987, CVE-2024-35966,
    CVE-2024-35977, CVE-2024-35866, CVE-2024-35975, CVE-2024-35965, CVE-2024-35933, CVE-2024-26936,
    CVE-2024-35889, CVE-2024-35863, CVE-2024-27002, CVE-2024-27018, CVE-2024-36021, CVE-2024-27019,
    CVE-2024-35921, CVE-2024-35870, CVE-2024-35956, CVE-2024-27016, CVE-2024-26996, CVE-2024-35878,
    CVE-2024-26988, CVE-2024-35888, CVE-2024-35936, CVE-2024-27014, CVE-2024-35883, CVE-2024-35862,
    CVE-2024-35945, CVE-2024-26983, CVE-2024-35982, CVE-2024-35924, CVE-2024-27004, CVE-2024-27008,
    CVE-2024-35963, CVE-2024-35909, CVE-2024-35911, CVE-2024-35973, CVE-2024-35887, CVE-2024-27009,
    CVE-2024-35980, CVE-2024-36026, CVE-2024-35969, CVE-2024-35954, CVE-2024-35864, CVE-2024-35953,
    CVE-2024-26998, CVE-2024-35931, CVE-2024-26981, CVE-2024-35971, CVE-2024-35934, CVE-2024-35929,
    CVE-2024-35918, CVE-2024-35937, CVE-2024-36018, CVE-2024-35877, CVE-2024-35925, CVE-2024-35981,
    CVE-2024-35985, CVE-2024-35942, CVE-2024-35922, CVE-2024-35952, CVE-2024-27011, CVE-2024-35944,
    CVE-2024-35905, CVE-2024-35880, CVE-2024-35882, CVE-2024-27005, CVE-2024-26991, CVE-2024-35871,
    CVE-2024-35926, CVE-2024-26992, CVE-2024-35894, CVE-2024-27017)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6893-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35979");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1006-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1009-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1009-nvidia-64k");
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
      'gke': '6.8.0-1006',
      'nvidia': '6.8.0-1009',
      'nvidia-64k': '6.8.0-1009'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6893-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-52699', 'CVE-2024-24857', 'CVE-2024-24858', 'CVE-2024-24859', 'CVE-2024-26811', 'CVE-2024-26817', 'CVE-2024-26921', 'CVE-2024-26922', 'CVE-2024-26923', 'CVE-2024-26925', 'CVE-2024-26926', 'CVE-2024-26928', 'CVE-2024-26936', 'CVE-2024-26980', 'CVE-2024-26981', 'CVE-2024-26982', 'CVE-2024-26983', 'CVE-2024-26984', 'CVE-2024-26985', 'CVE-2024-26986', 'CVE-2024-26987', 'CVE-2024-26988', 'CVE-2024-26989', 'CVE-2024-26990', 'CVE-2024-26991', 'CVE-2024-26992', 'CVE-2024-26993', 'CVE-2024-26994', 'CVE-2024-26995', 'CVE-2024-26996', 'CVE-2024-26997', 'CVE-2024-26998', 'CVE-2024-26999', 'CVE-2024-27000', 'CVE-2024-27001', 'CVE-2024-27002', 'CVE-2024-27003', 'CVE-2024-27004', 'CVE-2024-27005', 'CVE-2024-27006', 'CVE-2024-27007', 'CVE-2024-27008', 'CVE-2024-27009', 'CVE-2024-27010', 'CVE-2024-27011', 'CVE-2024-27012', 'CVE-2024-27013', 'CVE-2024-27014', 'CVE-2024-27015', 'CVE-2024-27016', 'CVE-2024-27017', 'CVE-2024-27018', 'CVE-2024-27019', 'CVE-2024-27020', 'CVE-2024-27021', 'CVE-2024-27022', 'CVE-2024-35860', 'CVE-2024-35861', 'CVE-2024-35862', 'CVE-2024-35863', 'CVE-2024-35864', 'CVE-2024-35865', 'CVE-2024-35866', 'CVE-2024-35867', 'CVE-2024-35868', 'CVE-2024-35869', 'CVE-2024-35870', 'CVE-2024-35871', 'CVE-2024-35872', 'CVE-2024-35873', 'CVE-2024-35875', 'CVE-2024-35877', 'CVE-2024-35878', 'CVE-2024-35879', 'CVE-2024-35880', 'CVE-2024-35882', 'CVE-2024-35883', 'CVE-2024-35884', 'CVE-2024-35885', 'CVE-2024-35886', 'CVE-2024-35887', 'CVE-2024-35888', 'CVE-2024-35889', 'CVE-2024-35890', 'CVE-2024-35891', 'CVE-2024-35892', 'CVE-2024-35893', 'CVE-2024-35894', 'CVE-2024-35895', 'CVE-2024-35896', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-35899', 'CVE-2024-35900', 'CVE-2024-35901', 'CVE-2024-35902', 'CVE-2024-35903', 'CVE-2024-35904', 'CVE-2024-35905', 'CVE-2024-35907', 'CVE-2024-35908', 'CVE-2024-35909', 'CVE-2024-35910', 'CVE-2024-35911', 'CVE-2024-35912', 'CVE-2024-35913', 'CVE-2024-35914', 'CVE-2024-35915', 'CVE-2024-35916', 'CVE-2024-35917', 'CVE-2024-35918', 'CVE-2024-35919', 'CVE-2024-35920', 'CVE-2024-35921', 'CVE-2024-35922', 'CVE-2024-35924', 'CVE-2024-35925', 'CVE-2024-35926', 'CVE-2024-35927', 'CVE-2024-35929', 'CVE-2024-35930', 'CVE-2024-35931', 'CVE-2024-35932', 'CVE-2024-35933', 'CVE-2024-35934', 'CVE-2024-35935', 'CVE-2024-35936', 'CVE-2024-35937', 'CVE-2024-35938', 'CVE-2024-35939', 'CVE-2024-35940', 'CVE-2024-35942', 'CVE-2024-35943', 'CVE-2024-35944', 'CVE-2024-35945', 'CVE-2024-35946', 'CVE-2024-35950', 'CVE-2024-35951', 'CVE-2024-35952', 'CVE-2024-35953', 'CVE-2024-35954', 'CVE-2024-35955', 'CVE-2024-35956', 'CVE-2024-35957', 'CVE-2024-35958', 'CVE-2024-35959', 'CVE-2024-35960', 'CVE-2024-35961', 'CVE-2024-35963', 'CVE-2024-35964', 'CVE-2024-35965', 'CVE-2024-35966', 'CVE-2024-35967', 'CVE-2024-35968', 'CVE-2024-35969', 'CVE-2024-35970', 'CVE-2024-35971', 'CVE-2024-35972', 'CVE-2024-35973', 'CVE-2024-35974', 'CVE-2024-35975', 'CVE-2024-35976', 'CVE-2024-35977', 'CVE-2024-35978', 'CVE-2024-35979', 'CVE-2024-35980', 'CVE-2024-35981', 'CVE-2024-35982', 'CVE-2024-35985', 'CVE-2024-36018', 'CVE-2024-36019', 'CVE-2024-36020', 'CVE-2024-36021', 'CVE-2024-36022', 'CVE-2024-36023', 'CVE-2024-36024', 'CVE-2024-36025', 'CVE-2024-36026', 'CVE-2024-36027');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6893-2');
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
