#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7089-6. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211400);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id(
    "CVE-2023-52887",
    "CVE-2023-52888",
    "CVE-2024-25741",
    "CVE-2024-39486",
    "CVE-2024-39487",
    "CVE-2024-41007",
    "CVE-2024-41010",
    "CVE-2024-41012",
    "CVE-2024-41015",
    "CVE-2024-41017",
    "CVE-2024-41018",
    "CVE-2024-41019",
    "CVE-2024-41020",
    "CVE-2024-41021",
    "CVE-2024-41022",
    "CVE-2024-41023",
    "CVE-2024-41025",
    "CVE-2024-41027",
    "CVE-2024-41028",
    "CVE-2024-41029",
    "CVE-2024-41030",
    "CVE-2024-41031",
    "CVE-2024-41032",
    "CVE-2024-41033",
    "CVE-2024-41034",
    "CVE-2024-41035",
    "CVE-2024-41036",
    "CVE-2024-41037",
    "CVE-2024-41038",
    "CVE-2024-41039",
    "CVE-2024-41041",
    "CVE-2024-41042",
    "CVE-2024-41044",
    "CVE-2024-41045",
    "CVE-2024-41046",
    "CVE-2024-41047",
    "CVE-2024-41048",
    "CVE-2024-41049",
    "CVE-2024-41050",
    "CVE-2024-41051",
    "CVE-2024-41052",
    "CVE-2024-41053",
    "CVE-2024-41054",
    "CVE-2024-41055",
    "CVE-2024-41056",
    "CVE-2024-41057",
    "CVE-2024-41058",
    "CVE-2024-41059",
    "CVE-2024-41060",
    "CVE-2024-41061",
    "CVE-2024-41062",
    "CVE-2024-41063",
    "CVE-2024-41064",
    "CVE-2024-41065",
    "CVE-2024-41066",
    "CVE-2024-41067",
    "CVE-2024-41068",
    "CVE-2024-41069",
    "CVE-2024-41070",
    "CVE-2024-41071",
    "CVE-2024-41072",
    "CVE-2024-41073",
    "CVE-2024-41074",
    "CVE-2024-41075",
    "CVE-2024-41076",
    "CVE-2024-41077",
    "CVE-2024-41078",
    "CVE-2024-41079",
    "CVE-2024-41080",
    "CVE-2024-41081",
    "CVE-2024-41082",
    "CVE-2024-41083",
    "CVE-2024-41084",
    "CVE-2024-41085",
    "CVE-2024-41086",
    "CVE-2024-41087",
    "CVE-2024-41088",
    "CVE-2024-41089",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-41092",
    "CVE-2024-41093",
    "CVE-2024-41094",
    "CVE-2024-41095",
    "CVE-2024-41096",
    "CVE-2024-41097",
    "CVE-2024-41098",
    "CVE-2024-42063",
    "CVE-2024-42064",
    "CVE-2024-42065",
    "CVE-2024-42066",
    "CVE-2024-42067",
    "CVE-2024-42068",
    "CVE-2024-42069",
    "CVE-2024-42070",
    "CVE-2024-42073",
    "CVE-2024-42074",
    "CVE-2024-42076",
    "CVE-2024-42077",
    "CVE-2024-42079",
    "CVE-2024-42080",
    "CVE-2024-42082",
    "CVE-2024-42084",
    "CVE-2024-42085",
    "CVE-2024-42086",
    "CVE-2024-42087",
    "CVE-2024-42088",
    "CVE-2024-42089",
    "CVE-2024-42090",
    "CVE-2024-42091",
    "CVE-2024-42092",
    "CVE-2024-42093",
    "CVE-2024-42094",
    "CVE-2024-42095",
    "CVE-2024-42096",
    "CVE-2024-42097",
    "CVE-2024-42098",
    "CVE-2024-42100",
    "CVE-2024-42101",
    "CVE-2024-42102",
    "CVE-2024-42103",
    "CVE-2024-42104",
    "CVE-2024-42105",
    "CVE-2024-42106",
    "CVE-2024-42108",
    "CVE-2024-42109",
    "CVE-2024-42110",
    "CVE-2024-42111",
    "CVE-2024-42112",
    "CVE-2024-42113",
    "CVE-2024-42114",
    "CVE-2024-42115",
    "CVE-2024-42117",
    "CVE-2024-42118",
    "CVE-2024-42119",
    "CVE-2024-42120",
    "CVE-2024-42121",
    "CVE-2024-42124",
    "CVE-2024-42126",
    "CVE-2024-42127",
    "CVE-2024-42128",
    "CVE-2024-42129",
    "CVE-2024-42130",
    "CVE-2024-42131",
    "CVE-2024-42132",
    "CVE-2024-42133",
    "CVE-2024-42135",
    "CVE-2024-42136",
    "CVE-2024-42137",
    "CVE-2024-42138",
    "CVE-2024-42140",
    "CVE-2024-42141",
    "CVE-2024-42142",
    "CVE-2024-42144",
    "CVE-2024-42145",
    "CVE-2024-42146",
    "CVE-2024-42147",
    "CVE-2024-42149",
    "CVE-2024-42150",
    "CVE-2024-42151",
    "CVE-2024-42152",
    "CVE-2024-42153",
    "CVE-2024-42155",
    "CVE-2024-42156",
    "CVE-2024-42157",
    "CVE-2024-42158",
    "CVE-2024-42161",
    "CVE-2024-42223",
    "CVE-2024-42225",
    "CVE-2024-42227",
    "CVE-2024-42229",
    "CVE-2024-42230",
    "CVE-2024-42231",
    "CVE-2024-42232",
    "CVE-2024-42234",
    "CVE-2024-42235",
    "CVE-2024-42236",
    "CVE-2024-42237",
    "CVE-2024-42238",
    "CVE-2024-42239",
    "CVE-2024-42240",
    "CVE-2024-42241",
    "CVE-2024-42243",
    "CVE-2024-42244",
    "CVE-2024-42245",
    "CVE-2024-42246",
    "CVE-2024-42247",
    "CVE-2024-42248",
    "CVE-2024-42250",
    "CVE-2024-42251",
    "CVE-2024-42252",
    "CVE-2024-42253",
    "CVE-2024-42271",
    "CVE-2024-42280",
    "CVE-2024-43855",
    "CVE-2024-43858"
  );
  script_xref(name:"USN", value:"7089-6");

  script_name(english:"Ubuntu 24.04 LTS : Linux kernel vulnerabilities (USN-7089-6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 24.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-7089-6 advisory.

    Chenyuan Yang discovered that the USB Gadget subsystem in the Linux kernel did not properly check for the
    device to be enabled before writing. A local attacker could possibly use this to cause a denial of
    service. (CVE-2024-25741)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM32 architecture;

    - MIPS architecture;

    - PA-RISC architecture;

    - PowerPC architecture;

    - RISC-V architecture;

    - S390 architecture;

    - x86 architecture;

    - Cryptographic API;

    - Serial ATA and Parallel ATA drivers;

    - Null block device driver;

    - Bluetooth drivers;

    - Cdrom driver;

    - Clock framework and drivers;

    - Hardware crypto device drivers;

    - CXL (Compute Express Link) drivers;

    - Cirrus firmware drivers;

    - GPIO subsystem;

    - GPU drivers;

    - I2C subsystem;

    - IIO subsystem;

    - InfiniBand drivers;

    - ISDN/mISDN subsystem;

    - LED subsystem;

    - Multiple devices driver;

    - Media drivers;

    - Fastrpc Driver;

    - Network drivers;

    - Microsoft Azure Network Adapter (MANA) driver;

    - Near Field Communication (NFC) drivers;

    - NVME drivers;

    - NVMEM (Non Volatile Memory) drivers;

    - PCI subsystem;

    - Pin controllers subsystem;

    - x86 platform drivers;

    - S/390 drivers;

    - SCSI drivers;

    - Thermal drivers;

    - TTY drivers;

    - UFS subsystem;

    - USB DSL drivers;

    - USB core drivers;

    - DesignWare USB3 driver;

    - USB Gadget drivers;

    - USB Serial drivers;

    - VFIO drivers;

    - VHOST drivers;

    - File systems infrastructure;

    - BTRFS file system;

    - GFS2 file system;

    - JFFS2 file system;

    - JFS file system;

    - Network file systems library;

    - Network file system client;

    - NILFS2 file system;

    - NTFS3 file system;

    - SMB network file system;

    - Memory management;

    - Netfilter;

    - Tracing infrastructure;

    - io_uring subsystem;

    - BPF subsystem;

    - Core kernel;

    - Bluetooth subsystem;

    - CAN network layer;

    - Ceph Core library;

    - Networking core;

    - IPv4 networking;

    - IPv6 networking;

    - IUCV driver;

    - MAC80211 subsystem;

    - Network traffic control;

    - Sun RPC protocol;

    - Wireless networking;

    - AMD SoC Alsa drivers;

    - SoC Audio for Freescale CPUs drivers;

    - MediaTek ASoC drivers;

    - SoC audio core drivers;

    - SOF drivers;

    - Sound sequencer drivers; (CVE-2024-41062, CVE-2024-41029, CVE-2024-42142, CVE-2024-41070,
    CVE-2024-41066, CVE-2024-42150, CVE-2024-42120, CVE-2023-52888, CVE-2024-42141, CVE-2024-41032,
    CVE-2024-42245, CVE-2024-41053, CVE-2024-42247, CVE-2024-42161, CVE-2024-42094, CVE-2024-41072,
    CVE-2024-42076, CVE-2024-42091, CVE-2024-42103, CVE-2024-41007, CVE-2024-42064, CVE-2024-41075,
    CVE-2024-42157, CVE-2024-42069, CVE-2024-41045, CVE-2024-42068, CVE-2024-42090, CVE-2024-41071,
    CVE-2024-42082, CVE-2024-42146, CVE-2024-41018, CVE-2024-42238, CVE-2024-41079, CVE-2024-42241,
    CVE-2024-42067, CVE-2024-42132, CVE-2024-42121, CVE-2024-41025, CVE-2024-42231, CVE-2024-42225,
    CVE-2024-41080, CVE-2024-41086, CVE-2024-41012, CVE-2024-42234, CVE-2024-41088, CVE-2024-42129,
    CVE-2024-42158, CVE-2024-41078, CVE-2024-41038, CVE-2024-41055, CVE-2024-42106, CVE-2024-42227,
    CVE-2024-42102, CVE-2024-41082, CVE-2024-42108, CVE-2024-41085, CVE-2024-41020, CVE-2024-41054,
    CVE-2024-42085, CVE-2024-42140, CVE-2024-42089, CVE-2024-41047, CVE-2024-42092, CVE-2024-41044,
    CVE-2024-42246, CVE-2024-41035, CVE-2024-42250, CVE-2024-42070, CVE-2024-41039, CVE-2024-41061,
    CVE-2024-42147, CVE-2024-42104, CVE-2024-41090, CVE-2024-41096, CVE-2024-41063, CVE-2024-41084,
    CVE-2024-41059, CVE-2024-41097, CVE-2024-41089, CVE-2024-42093, CVE-2024-42126, CVE-2024-42135,
    CVE-2024-42128, CVE-2024-42098, CVE-2024-42105, CVE-2024-42124, CVE-2024-42101, CVE-2024-41091,
    CVE-2024-42127, CVE-2024-41077, CVE-2024-42111, CVE-2024-41037, CVE-2024-42136, CVE-2024-41083,
    CVE-2024-42243, CVE-2024-41033, CVE-2024-41046, CVE-2024-42230, CVE-2024-42080, CVE-2024-42096,
    CVE-2024-42100, CVE-2024-42236, CVE-2024-41022, CVE-2024-42086, CVE-2024-42251, CVE-2024-41015,
    CVE-2024-41027, CVE-2024-42155, CVE-2024-42117, CVE-2024-41036, CVE-2024-42133, CVE-2024-41010,
    CVE-2024-42151, CVE-2024-42118, CVE-2024-39486, CVE-2024-42066, CVE-2024-42131, CVE-2024-42223,
    CVE-2024-41081, CVE-2024-42244, CVE-2024-41073, CVE-2024-42114, CVE-2024-42252, CVE-2024-42248,
    CVE-2024-42110, CVE-2024-41051, CVE-2023-52887, CVE-2024-42156, CVE-2024-41074, CVE-2024-41017,
    CVE-2024-42079, CVE-2024-41034, CVE-2024-41028, CVE-2024-42109, CVE-2024-42235, CVE-2024-41058,
    CVE-2024-42232, CVE-2024-42084, CVE-2024-41076, CVE-2024-41030, CVE-2024-41023, CVE-2024-42271,
    CVE-2024-41050, CVE-2024-41042, CVE-2024-41031, CVE-2024-42112, CVE-2024-41092, CVE-2024-42253,
    CVE-2024-42152, CVE-2024-41049, CVE-2024-42237, CVE-2024-41095, CVE-2024-42280, CVE-2024-42153,
    CVE-2024-42115, CVE-2024-42130, CVE-2024-41064, CVE-2024-42077, CVE-2024-41067, CVE-2024-42137,
    CVE-2024-41019, CVE-2024-42240, CVE-2024-41093, CVE-2024-41048, CVE-2024-42063, CVE-2024-42113,
    CVE-2024-42145, CVE-2024-42073, CVE-2024-43858, CVE-2024-42088, CVE-2024-41069, CVE-2024-41068,
    CVE-2024-42138, CVE-2024-41065, CVE-2024-42087, CVE-2024-42239, CVE-2024-42149, CVE-2024-41021,
    CVE-2024-42065, CVE-2024-39487, CVE-2024-41052, CVE-2024-42095, CVE-2024-42074, CVE-2024-42097,
    CVE-2024-41098, CVE-2024-41057, CVE-2024-41060, CVE-2024-42119, CVE-2024-42229, CVE-2024-43855,
    CVE-2024-41056, CVE-2024-41041, CVE-2024-42144, CVE-2024-41087, CVE-2024-41094)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7089-6");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43858");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1013-gke");
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
if (! ('24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '24.04': {
    '6.8.0': {
      'gke': '6.8.0-1013'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7089-6');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-52887', 'CVE-2023-52888', 'CVE-2024-25741', 'CVE-2024-39486', 'CVE-2024-39487', 'CVE-2024-41007', 'CVE-2024-41010', 'CVE-2024-41012', 'CVE-2024-41015', 'CVE-2024-41017', 'CVE-2024-41018', 'CVE-2024-41019', 'CVE-2024-41020', 'CVE-2024-41021', 'CVE-2024-41022', 'CVE-2024-41023', 'CVE-2024-41025', 'CVE-2024-41027', 'CVE-2024-41028', 'CVE-2024-41029', 'CVE-2024-41030', 'CVE-2024-41031', 'CVE-2024-41032', 'CVE-2024-41033', 'CVE-2024-41034', 'CVE-2024-41035', 'CVE-2024-41036', 'CVE-2024-41037', 'CVE-2024-41038', 'CVE-2024-41039', 'CVE-2024-41041', 'CVE-2024-41042', 'CVE-2024-41044', 'CVE-2024-41045', 'CVE-2024-41046', 'CVE-2024-41047', 'CVE-2024-41048', 'CVE-2024-41049', 'CVE-2024-41050', 'CVE-2024-41051', 'CVE-2024-41052', 'CVE-2024-41053', 'CVE-2024-41054', 'CVE-2024-41055', 'CVE-2024-41056', 'CVE-2024-41057', 'CVE-2024-41058', 'CVE-2024-41059', 'CVE-2024-41060', 'CVE-2024-41061', 'CVE-2024-41062', 'CVE-2024-41063', 'CVE-2024-41064', 'CVE-2024-41065', 'CVE-2024-41066', 'CVE-2024-41067', 'CVE-2024-41068', 'CVE-2024-41069', 'CVE-2024-41070', 'CVE-2024-41071', 'CVE-2024-41072', 'CVE-2024-41073', 'CVE-2024-41074', 'CVE-2024-41075', 'CVE-2024-41076', 'CVE-2024-41077', 'CVE-2024-41078', 'CVE-2024-41079', 'CVE-2024-41080', 'CVE-2024-41081', 'CVE-2024-41082', 'CVE-2024-41083', 'CVE-2024-41084', 'CVE-2024-41085', 'CVE-2024-41086', 'CVE-2024-41087', 'CVE-2024-41088', 'CVE-2024-41089', 'CVE-2024-41090', 'CVE-2024-41091', 'CVE-2024-41092', 'CVE-2024-41093', 'CVE-2024-41094', 'CVE-2024-41095', 'CVE-2024-41096', 'CVE-2024-41097', 'CVE-2024-41098', 'CVE-2024-42063', 'CVE-2024-42064', 'CVE-2024-42065', 'CVE-2024-42066', 'CVE-2024-42067', 'CVE-2024-42068', 'CVE-2024-42069', 'CVE-2024-42070', 'CVE-2024-42073', 'CVE-2024-42074', 'CVE-2024-42076', 'CVE-2024-42077', 'CVE-2024-42079', 'CVE-2024-42080', 'CVE-2024-42082', 'CVE-2024-42084', 'CVE-2024-42085', 'CVE-2024-42086', 'CVE-2024-42087', 'CVE-2024-42088', 'CVE-2024-42089', 'CVE-2024-42090', 'CVE-2024-42091', 'CVE-2024-42092', 'CVE-2024-42093', 'CVE-2024-42094', 'CVE-2024-42095', 'CVE-2024-42096', 'CVE-2024-42097', 'CVE-2024-42098', 'CVE-2024-42100', 'CVE-2024-42101', 'CVE-2024-42102', 'CVE-2024-42103', 'CVE-2024-42104', 'CVE-2024-42105', 'CVE-2024-42106', 'CVE-2024-42108', 'CVE-2024-42109', 'CVE-2024-42110', 'CVE-2024-42111', 'CVE-2024-42112', 'CVE-2024-42113', 'CVE-2024-42114', 'CVE-2024-42115', 'CVE-2024-42117', 'CVE-2024-42118', 'CVE-2024-42119', 'CVE-2024-42120', 'CVE-2024-42121', 'CVE-2024-42124', 'CVE-2024-42126', 'CVE-2024-42127', 'CVE-2024-42128', 'CVE-2024-42129', 'CVE-2024-42130', 'CVE-2024-42131', 'CVE-2024-42132', 'CVE-2024-42133', 'CVE-2024-42135', 'CVE-2024-42136', 'CVE-2024-42137', 'CVE-2024-42138', 'CVE-2024-42140', 'CVE-2024-42141', 'CVE-2024-42142', 'CVE-2024-42144', 'CVE-2024-42145', 'CVE-2024-42146', 'CVE-2024-42147', 'CVE-2024-42149', 'CVE-2024-42150', 'CVE-2024-42151', 'CVE-2024-42152', 'CVE-2024-42153', 'CVE-2024-42155', 'CVE-2024-42156', 'CVE-2024-42157', 'CVE-2024-42158', 'CVE-2024-42161', 'CVE-2024-42223', 'CVE-2024-42225', 'CVE-2024-42227', 'CVE-2024-42229', 'CVE-2024-42230', 'CVE-2024-42231', 'CVE-2024-42232', 'CVE-2024-42234', 'CVE-2024-42235', 'CVE-2024-42236', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42239', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42245', 'CVE-2024-42246', 'CVE-2024-42247', 'CVE-2024-42248', 'CVE-2024-42250', 'CVE-2024-42251', 'CVE-2024-42252', 'CVE-2024-42253', 'CVE-2024-42271', 'CVE-2024-42280', 'CVE-2024-43855', 'CVE-2024-43858');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7089-6');
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
