#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6952-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205289);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id(
    "CVE-2023-52882",
    "CVE-2024-25742",
    "CVE-2024-27394",
    "CVE-2024-27395",
    "CVE-2024-27396",
    "CVE-2024-27398",
    "CVE-2024-27399",
    "CVE-2024-27400",
    "CVE-2024-27401",
    "CVE-2024-35846",
    "CVE-2024-35847",
    "CVE-2024-35848",
    "CVE-2024-35849",
    "CVE-2024-35850",
    "CVE-2024-35851",
    "CVE-2024-35852",
    "CVE-2024-35853",
    "CVE-2024-35854",
    "CVE-2024-35855",
    "CVE-2024-35856",
    "CVE-2024-35857",
    "CVE-2024-35858",
    "CVE-2024-35859",
    "CVE-2024-35947",
    "CVE-2024-35949",
    "CVE-2024-35983",
    "CVE-2024-35984",
    "CVE-2024-35986",
    "CVE-2024-35987",
    "CVE-2024-35988",
    "CVE-2024-35989",
    "CVE-2024-35990",
    "CVE-2024-35991",
    "CVE-2024-35992",
    "CVE-2024-35993",
    "CVE-2024-35994",
    "CVE-2024-35996",
    "CVE-2024-35997",
    "CVE-2024-35998",
    "CVE-2024-35999",
    "CVE-2024-36000",
    "CVE-2024-36001",
    "CVE-2024-36002",
    "CVE-2024-36003",
    "CVE-2024-36004",
    "CVE-2024-36005",
    "CVE-2024-36006",
    "CVE-2024-36007",
    "CVE-2024-36008",
    "CVE-2024-36009",
    "CVE-2024-36011",
    "CVE-2024-36012",
    "CVE-2024-36013",
    "CVE-2024-36014",
    "CVE-2024-36016",
    "CVE-2024-36017",
    "CVE-2024-36028",
    "CVE-2024-36029",
    "CVE-2024-36030",
    "CVE-2024-36031",
    "CVE-2024-36032",
    "CVE-2024-36033",
    "CVE-2024-36880",
    "CVE-2024-36881",
    "CVE-2024-36882",
    "CVE-2024-36883",
    "CVE-2024-36884",
    "CVE-2024-36886",
    "CVE-2024-36887",
    "CVE-2024-36888",
    "CVE-2024-36889",
    "CVE-2024-36890",
    "CVE-2024-36891",
    "CVE-2024-36892",
    "CVE-2024-36893",
    "CVE-2024-36894",
    "CVE-2024-36895",
    "CVE-2024-36896",
    "CVE-2024-36897",
    "CVE-2024-36898",
    "CVE-2024-36899",
    "CVE-2024-36900",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36903",
    "CVE-2024-36904",
    "CVE-2024-36905",
    "CVE-2024-36906",
    "CVE-2024-36908",
    "CVE-2024-36909",
    "CVE-2024-36910",
    "CVE-2024-36911",
    "CVE-2024-36912",
    "CVE-2024-36913",
    "CVE-2024-36914",
    "CVE-2024-36915",
    "CVE-2024-36916",
    "CVE-2024-36917",
    "CVE-2024-36918",
    "CVE-2024-36919",
    "CVE-2024-36920",
    "CVE-2024-36921",
    "CVE-2024-36922",
    "CVE-2024-36923",
    "CVE-2024-36924",
    "CVE-2024-36925",
    "CVE-2024-36926",
    "CVE-2024-36927",
    "CVE-2024-36928",
    "CVE-2024-36929",
    "CVE-2024-36930",
    "CVE-2024-36931",
    "CVE-2024-36932",
    "CVE-2024-36933",
    "CVE-2024-36934",
    "CVE-2024-36935",
    "CVE-2024-36936",
    "CVE-2024-36937",
    "CVE-2024-36938",
    "CVE-2024-36939",
    "CVE-2024-36940",
    "CVE-2024-36941",
    "CVE-2024-36943",
    "CVE-2024-36944",
    "CVE-2024-36945",
    "CVE-2024-36946",
    "CVE-2024-36947",
    "CVE-2024-36948",
    "CVE-2024-36949",
    "CVE-2024-36950",
    "CVE-2024-36951",
    "CVE-2024-36952",
    "CVE-2024-36953",
    "CVE-2024-36954",
    "CVE-2024-36955",
    "CVE-2024-36956",
    "CVE-2024-36957",
    "CVE-2024-36958",
    "CVE-2024-36959",
    "CVE-2024-36960",
    "CVE-2024-36961",
    "CVE-2024-36962",
    "CVE-2024-36963",
    "CVE-2024-36964",
    "CVE-2024-36965",
    "CVE-2024-36966",
    "CVE-2024-36967",
    "CVE-2024-36968",
    "CVE-2024-36969",
    "CVE-2024-36975",
    "CVE-2024-36977",
    "CVE-2024-36979",
    "CVE-2024-38538",
    "CVE-2024-38539",
    "CVE-2024-38540",
    "CVE-2024-38541",
    "CVE-2024-38542",
    "CVE-2024-38543",
    "CVE-2024-38544",
    "CVE-2024-38545",
    "CVE-2024-38546",
    "CVE-2024-38547",
    "CVE-2024-38548",
    "CVE-2024-38549",
    "CVE-2024-38550",
    "CVE-2024-38551",
    "CVE-2024-38552",
    "CVE-2024-38553",
    "CVE-2024-38554",
    "CVE-2024-38555",
    "CVE-2024-38556",
    "CVE-2024-38557",
    "CVE-2024-38558",
    "CVE-2024-38559",
    "CVE-2024-38560",
    "CVE-2024-38561",
    "CVE-2024-38562",
    "CVE-2024-38563",
    "CVE-2024-38564",
    "CVE-2024-38565",
    "CVE-2024-38566",
    "CVE-2024-38567",
    "CVE-2024-38568",
    "CVE-2024-38569",
    "CVE-2024-38570",
    "CVE-2024-38571",
    "CVE-2024-38572",
    "CVE-2024-38573",
    "CVE-2024-38574",
    "CVE-2024-38575",
    "CVE-2024-38576",
    "CVE-2024-38577",
    "CVE-2024-38578",
    "CVE-2024-38579",
    "CVE-2024-38580",
    "CVE-2024-38582",
    "CVE-2024-38583",
    "CVE-2024-38584",
    "CVE-2024-38585",
    "CVE-2024-38586",
    "CVE-2024-38587",
    "CVE-2024-38588",
    "CVE-2024-38589",
    "CVE-2024-38590",
    "CVE-2024-38591",
    "CVE-2024-38592",
    "CVE-2024-38593",
    "CVE-2024-38594",
    "CVE-2024-38595",
    "CVE-2024-38596",
    "CVE-2024-38597",
    "CVE-2024-38598",
    "CVE-2024-38599",
    "CVE-2024-38600",
    "CVE-2024-38601",
    "CVE-2024-38602",
    "CVE-2024-38603",
    "CVE-2024-38604",
    "CVE-2024-38605",
    "CVE-2024-38606",
    "CVE-2024-38607",
    "CVE-2024-38610",
    "CVE-2024-38611",
    "CVE-2024-38612",
    "CVE-2024-38613",
    "CVE-2024-38614",
    "CVE-2024-38615",
    "CVE-2024-38616",
    "CVE-2024-38617",
    "CVE-2024-38620",
    "CVE-2024-39482",
    "CVE-2024-41011",
    "CVE-2024-42134"
  );
  script_xref(name:"USN", value:"6952-1");

  script_name(english:"Ubuntu 24.04 LTS : Linux kernel vulnerabilities (USN-6952-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 24.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6952-1 advisory.

    Benedict Schlter, Supraja Sridhara, Andrin Bertschi, and Shweta Shinde discovered that an untrusted
    hypervisor could inject malicious #VC interrupts and compromise the security guarantees of AMD SEV-SNP.
    This flaw is known as WeSee. A local attacker in control of the hypervisor could use this to expose
    sensitive information or possibly execute arbitrary code in the trusted execution environment.
    (CVE-2024-25742)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM32 architecture;

    - ARM64 architecture;

    - M68K architecture;

    - OpenRISC architecture;

    - PowerPC architecture;

    - RISC-V architecture;

    - x86 architecture;

    - Block layer subsystem;

    - Accessibility subsystem;

    - Bluetooth drivers;

    - Clock framework and drivers;

    - CPU frequency scaling framework;

    - Hardware crypto device drivers;

    - DMA engine subsystem;

    - DPLL subsystem;

    - FireWire subsystem;

    - EFI core;

    - Qualcomm firmware drivers;

    - GPIO subsystem;

    - GPU drivers;

    - HID subsystem;

    - Microsoft Hyper-V drivers;

    - I2C subsystem;

    - InfiniBand drivers;

    - IOMMU subsystem;

    - IRQ chip drivers;

    - Macintosh device drivers;

    - Multiple devices driver;

    - Media drivers;

    - EEPROM drivers;

    - MMC subsystem;

    - Network drivers;

    - STMicroelectronics network drivers;

    - Device tree and open firmware driver;

    - HiSilicon SoC PMU drivers;

    - PHY drivers;

    - Pin controllers subsystem;

    - Remote Processor subsystem;

    - S/390 drivers;

    - SCSI drivers;

    - SPI subsystem;

    - Media staging drivers;

    - Thermal drivers;

    - TTY drivers;

    - Userspace I/O drivers;

    - USB subsystem;

    - DesignWare USB3 driver;

    - ACRN Hypervisor Service Module driver;

    - Virtio drivers;

    - 9P distributed file system;

    - BTRFS file system;

    - eCrypt file system;

    - EROFS file system;

    - File systems infrastructure;

    - GFS2 file system;

    - JFFS2 file system;

    - Network file systems library;

    - Network file system client;

    - Network file system server daemon;

    - NILFS2 file system;

    - Proc file system;

    - SMB network file system;

    - Tracing file system;

    - Mellanox drivers;

    - Memory management;

    - Socket messages infrastructure;

    - Slab allocator;

    - Tracing infrastructure;

    - User-space API (UAPI);

    - Core kernel;

    - BPF subsystem;

    - DMA mapping infrastructure;

    - RCU subsystem;

    - Dynamic debug library;

    - KUnit library;

    - Maple Tree data structure library;

    - Heterogeneous memory management;

    - Amateur Radio drivers;

    - Bluetooth subsystem;

    - Ethernet bridge;

    - Networking core;

    - IPv4 networking;

    - IPv6 networking;

    - Multipath TCP;

    - Netfilter;

    - NET/ROM layer;

    - NFC subsystem;

    - NSH protocol;

    - Open vSwitch;

    - Phonet protocol;

    - SMC sockets;

    - TIPC protocol;

    - Unix domain sockets;

    - Wireless networking;

    - Key management;

    - ALSA framework;

    - HD-audio driver;

    - Kirkwood ASoC drivers;

    - MediaTek ASoC drivers; (CVE-2024-38601, CVE-2024-36935, CVE-2024-35991, CVE-2024-36032, CVE-2024-35988,
    CVE-2024-36886, CVE-2024-36913, CVE-2024-36928, CVE-2024-38553, CVE-2024-36927, CVE-2024-38615,
    CVE-2024-36958, CVE-2024-36977, CVE-2024-36889, CVE-2024-38554, CVE-2024-38590, CVE-2024-42134,
    CVE-2024-35857, CVE-2024-35850, CVE-2024-35986, CVE-2024-36921, CVE-2024-38569, CVE-2024-36966,
    CVE-2024-38542, CVE-2024-38585, CVE-2024-36884, CVE-2024-36006, CVE-2024-38577, CVE-2024-36016,
    CVE-2024-38584, CVE-2024-36887, CVE-2024-38598, CVE-2024-35994, CVE-2024-38603, CVE-2024-35998,
    CVE-2024-27401, CVE-2024-35852, CVE-2024-36944, CVE-2024-38572, CVE-2024-36917, CVE-2024-36943,
    CVE-2024-36009, CVE-2024-38587, CVE-2024-35949, CVE-2024-36945, CVE-2024-36004, CVE-2024-36919,
    CVE-2024-27398, CVE-2024-38582, CVE-2024-35847, CVE-2024-38580, CVE-2024-38602, CVE-2024-36916,
    CVE-2024-36903, CVE-2024-38555, CVE-2024-36952, CVE-2024-38589, CVE-2024-27394, CVE-2024-36933,
    CVE-2024-36975, CVE-2024-38591, CVE-2024-38612, CVE-2024-36939, CVE-2024-35983, CVE-2024-38607,
    CVE-2024-36929, CVE-2024-35849, CVE-2024-36941, CVE-2024-35858, CVE-2024-38599, CVE-2024-35996,
    CVE-2024-36031, CVE-2024-36931, CVE-2024-35990, CVE-2024-35851, CVE-2024-38556, CVE-2024-36000,
    CVE-2024-36910, CVE-2024-38573, CVE-2024-36906, CVE-2024-36951, CVE-2024-38604, CVE-2024-38613,
    CVE-2024-38547, CVE-2024-36014, CVE-2024-36949, CVE-2024-36033, CVE-2024-38597, CVE-2024-36880,
    CVE-2024-38594, CVE-2024-36894, CVE-2024-38546, CVE-2024-36947, CVE-2024-38541, CVE-2024-35989,
    CVE-2024-27399, CVE-2024-38550, CVE-2024-36922, CVE-2024-36008, CVE-2024-38540, CVE-2024-36924,
    CVE-2024-36892, CVE-2024-38549, CVE-2024-36882, CVE-2024-36908, CVE-2024-38566, CVE-2024-36005,
    CVE-2024-38583, CVE-2024-36968, CVE-2024-36017, CVE-2024-38565, CVE-2024-36881, CVE-2024-38611,
    CVE-2024-36897, CVE-2024-38560, CVE-2024-36923, CVE-2024-38575, CVE-2024-36899, CVE-2024-38570,
    CVE-2024-36898, CVE-2024-36896, CVE-2024-38559, CVE-2024-38588, CVE-2024-38606, CVE-2024-38551,
    CVE-2024-36891, CVE-2024-38567, CVE-2024-36895, CVE-2024-35993, CVE-2024-38552, CVE-2024-36925,
    CVE-2024-36964, CVE-2024-36888, CVE-2024-36956, CVE-2024-36946, CVE-2024-38600, CVE-2024-35997,
    CVE-2024-36912, CVE-2024-35984, CVE-2024-35848, CVE-2024-38545, CVE-2024-38563, CVE-2024-36918,
    CVE-2024-36001, CVE-2024-36957, CVE-2024-38576, CVE-2024-36030, CVE-2024-38574, CVE-2024-36963,
    CVE-2024-36890, CVE-2024-36960, CVE-2024-36901, CVE-2024-38614, CVE-2024-35859, CVE-2024-38593,
    CVE-2024-36904, CVE-2024-36012, CVE-2024-38578, CVE-2024-36011, CVE-2024-36930, CVE-2024-36938,
    CVE-2024-36893, CVE-2024-35987, CVE-2024-36905, CVE-2024-35853, CVE-2024-36003, CVE-2024-38562,
    CVE-2024-38617, CVE-2024-35855, CVE-2024-36965, CVE-2024-38596, CVE-2024-38558, CVE-2024-38568,
    CVE-2024-36955, CVE-2024-36029, CVE-2024-36967, CVE-2024-36940, CVE-2024-38595, CVE-2024-36028,
    CVE-2024-38610, CVE-2024-36911, CVE-2024-35999, CVE-2024-35854, CVE-2024-38571, CVE-2024-38548,
    CVE-2024-36948, CVE-2024-36002, CVE-2024-36961, CVE-2024-36900, CVE-2024-36932, CVE-2024-36902,
    CVE-2024-35992, CVE-2024-36914, CVE-2024-38592, CVE-2024-38616, CVE-2024-27400, CVE-2024-36937,
    CVE-2024-36920, CVE-2024-38586, CVE-2024-36909, CVE-2024-35846, CVE-2024-39482, CVE-2024-38579,
    CVE-2024-38539, CVE-2024-27395, CVE-2024-36962, CVE-2024-36013, CVE-2024-27396, CVE-2024-38557,
    CVE-2024-36953, CVE-2024-41011, CVE-2023-52882, CVE-2024-36969, CVE-2024-36007, CVE-2024-35856,
    CVE-2024-38605, CVE-2024-36915, CVE-2024-36979, CVE-2024-36954, CVE-2024-38538, CVE-2024-36950,
    CVE-2024-36926, CVE-2024-38544, CVE-2024-36959, CVE-2024-38561, CVE-2024-36883, CVE-2024-36936,
    CVE-2024-38564, CVE-2024-38543, CVE-2024-36934, CVE-2024-35947, CVE-2024-38620)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6952-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41011");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1010-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1010-oracle-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1011-nvidia-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1011-nvidia-lowlatency-64k");
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
      'oracle': '6.8.0-1010',
      'oracle-64k': '6.8.0-1010',
      'nvidia-lowlatency': '6.8.0-1011',
      'nvidia-lowlatency-64k': '6.8.0-1011'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6952-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-52882', 'CVE-2024-25742', 'CVE-2024-27394', 'CVE-2024-27395', 'CVE-2024-27396', 'CVE-2024-27398', 'CVE-2024-27399', 'CVE-2024-27400', 'CVE-2024-27401', 'CVE-2024-35846', 'CVE-2024-35847', 'CVE-2024-35848', 'CVE-2024-35849', 'CVE-2024-35850', 'CVE-2024-35851', 'CVE-2024-35852', 'CVE-2024-35853', 'CVE-2024-35854', 'CVE-2024-35855', 'CVE-2024-35856', 'CVE-2024-35857', 'CVE-2024-35858', 'CVE-2024-35859', 'CVE-2024-35947', 'CVE-2024-35949', 'CVE-2024-35983', 'CVE-2024-35984', 'CVE-2024-35986', 'CVE-2024-35987', 'CVE-2024-35988', 'CVE-2024-35989', 'CVE-2024-35990', 'CVE-2024-35991', 'CVE-2024-35992', 'CVE-2024-35993', 'CVE-2024-35994', 'CVE-2024-35996', 'CVE-2024-35997', 'CVE-2024-35998', 'CVE-2024-35999', 'CVE-2024-36000', 'CVE-2024-36001', 'CVE-2024-36002', 'CVE-2024-36003', 'CVE-2024-36004', 'CVE-2024-36005', 'CVE-2024-36006', 'CVE-2024-36007', 'CVE-2024-36008', 'CVE-2024-36009', 'CVE-2024-36011', 'CVE-2024-36012', 'CVE-2024-36013', 'CVE-2024-36014', 'CVE-2024-36016', 'CVE-2024-36017', 'CVE-2024-36028', 'CVE-2024-36029', 'CVE-2024-36030', 'CVE-2024-36031', 'CVE-2024-36032', 'CVE-2024-36033', 'CVE-2024-36880', 'CVE-2024-36881', 'CVE-2024-36882', 'CVE-2024-36883', 'CVE-2024-36884', 'CVE-2024-36886', 'CVE-2024-36887', 'CVE-2024-36888', 'CVE-2024-36889', 'CVE-2024-36890', 'CVE-2024-36891', 'CVE-2024-36892', 'CVE-2024-36893', 'CVE-2024-36894', 'CVE-2024-36895', 'CVE-2024-36896', 'CVE-2024-36897', 'CVE-2024-36898', 'CVE-2024-36899', 'CVE-2024-36900', 'CVE-2024-36901', 'CVE-2024-36902', 'CVE-2024-36903', 'CVE-2024-36904', 'CVE-2024-36905', 'CVE-2024-36906', 'CVE-2024-36908', 'CVE-2024-36909', 'CVE-2024-36910', 'CVE-2024-36911', 'CVE-2024-36912', 'CVE-2024-36913', 'CVE-2024-36914', 'CVE-2024-36915', 'CVE-2024-36916', 'CVE-2024-36917', 'CVE-2024-36918', 'CVE-2024-36919', 'CVE-2024-36920', 'CVE-2024-36921', 'CVE-2024-36922', 'CVE-2024-36923', 'CVE-2024-36924', 'CVE-2024-36925', 'CVE-2024-36926', 'CVE-2024-36927', 'CVE-2024-36928', 'CVE-2024-36929', 'CVE-2024-36930', 'CVE-2024-36931', 'CVE-2024-36932', 'CVE-2024-36933', 'CVE-2024-36934', 'CVE-2024-36935', 'CVE-2024-36936', 'CVE-2024-36937', 'CVE-2024-36938', 'CVE-2024-36939', 'CVE-2024-36940', 'CVE-2024-36941', 'CVE-2024-36943', 'CVE-2024-36944', 'CVE-2024-36945', 'CVE-2024-36946', 'CVE-2024-36947', 'CVE-2024-36948', 'CVE-2024-36949', 'CVE-2024-36950', 'CVE-2024-36951', 'CVE-2024-36952', 'CVE-2024-36953', 'CVE-2024-36954', 'CVE-2024-36955', 'CVE-2024-36956', 'CVE-2024-36957', 'CVE-2024-36958', 'CVE-2024-36959', 'CVE-2024-36960', 'CVE-2024-36961', 'CVE-2024-36962', 'CVE-2024-36963', 'CVE-2024-36964', 'CVE-2024-36965', 'CVE-2024-36966', 'CVE-2024-36967', 'CVE-2024-36968', 'CVE-2024-36969', 'CVE-2024-36975', 'CVE-2024-36977', 'CVE-2024-36979', 'CVE-2024-38538', 'CVE-2024-38539', 'CVE-2024-38540', 'CVE-2024-38541', 'CVE-2024-38542', 'CVE-2024-38543', 'CVE-2024-38544', 'CVE-2024-38545', 'CVE-2024-38546', 'CVE-2024-38547', 'CVE-2024-38548', 'CVE-2024-38549', 'CVE-2024-38550', 'CVE-2024-38551', 'CVE-2024-38552', 'CVE-2024-38553', 'CVE-2024-38554', 'CVE-2024-38555', 'CVE-2024-38556', 'CVE-2024-38557', 'CVE-2024-38558', 'CVE-2024-38559', 'CVE-2024-38560', 'CVE-2024-38561', 'CVE-2024-38562', 'CVE-2024-38563', 'CVE-2024-38564', 'CVE-2024-38565', 'CVE-2024-38566', 'CVE-2024-38567', 'CVE-2024-38568', 'CVE-2024-38569', 'CVE-2024-38570', 'CVE-2024-38571', 'CVE-2024-38572', 'CVE-2024-38573', 'CVE-2024-38574', 'CVE-2024-38575', 'CVE-2024-38576', 'CVE-2024-38577', 'CVE-2024-38578', 'CVE-2024-38579', 'CVE-2024-38580', 'CVE-2024-38582', 'CVE-2024-38583', 'CVE-2024-38584', 'CVE-2024-38585', 'CVE-2024-38586', 'CVE-2024-38587', 'CVE-2024-38588', 'CVE-2024-38589', 'CVE-2024-38590', 'CVE-2024-38591', 'CVE-2024-38592', 'CVE-2024-38593', 'CVE-2024-38594', 'CVE-2024-38595', 'CVE-2024-38596', 'CVE-2024-38597', 'CVE-2024-38598', 'CVE-2024-38599', 'CVE-2024-38600', 'CVE-2024-38601', 'CVE-2024-38602', 'CVE-2024-38603', 'CVE-2024-38604', 'CVE-2024-38605', 'CVE-2024-38606', 'CVE-2024-38607', 'CVE-2024-38610', 'CVE-2024-38611', 'CVE-2024-38612', 'CVE-2024-38613', 'CVE-2024-38614', 'CVE-2024-38615', 'CVE-2024-38616', 'CVE-2024-38617', 'CVE-2024-38620', 'CVE-2024-39482', 'CVE-2024-41011', 'CVE-2024-42134');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6952-1');
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
