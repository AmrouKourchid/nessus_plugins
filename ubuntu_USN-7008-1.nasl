#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7008-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207235);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/13");

  script_cve_id(
    "CVE-2022-48772",
    "CVE-2023-52884",
    "CVE-2024-23848",
    "CVE-2024-31076",
    "CVE-2024-32936",
    "CVE-2024-33619",
    "CVE-2024-33621",
    "CVE-2024-33847",
    "CVE-2024-34027",
    "CVE-2024-34030",
    "CVE-2024-34777",
    "CVE-2024-35247",
    "CVE-2024-36015",
    "CVE-2024-36244",
    "CVE-2024-36270",
    "CVE-2024-36281",
    "CVE-2024-36286",
    "CVE-2024-36288",
    "CVE-2024-36477",
    "CVE-2024-36478",
    "CVE-2024-36479",
    "CVE-2024-36481",
    "CVE-2024-36484",
    "CVE-2024-36489",
    "CVE-2024-36971",
    "CVE-2024-36972",
    "CVE-2024-36973",
    "CVE-2024-36974",
    "CVE-2024-36978",
    "CVE-2024-37021",
    "CVE-2024-37026",
    "CVE-2024-37078",
    "CVE-2024-37354",
    "CVE-2024-37356",
    "CVE-2024-38306",
    "CVE-2024-38381",
    "CVE-2024-38384",
    "CVE-2024-38385",
    "CVE-2024-38388",
    "CVE-2024-38390",
    "CVE-2024-38618",
    "CVE-2024-38619",
    "CVE-2024-38621",
    "CVE-2024-38622",
    "CVE-2024-38623",
    "CVE-2024-38624",
    "CVE-2024-38625",
    "CVE-2024-38627",
    "CVE-2024-38628",
    "CVE-2024-38629",
    "CVE-2024-38630",
    "CVE-2024-38632",
    "CVE-2024-38633",
    "CVE-2024-38634",
    "CVE-2024-38635",
    "CVE-2024-38636",
    "CVE-2024-38637",
    "CVE-2024-38659",
    "CVE-2024-38661",
    "CVE-2024-38662",
    "CVE-2024-38663",
    "CVE-2024-38664",
    "CVE-2024-38667",
    "CVE-2024-38780",
    "CVE-2024-39276",
    "CVE-2024-39277",
    "CVE-2024-39291",
    "CVE-2024-39292",
    "CVE-2024-39296",
    "CVE-2024-39298",
    "CVE-2024-39301",
    "CVE-2024-39371",
    "CVE-2024-39461",
    "CVE-2024-39462",
    "CVE-2024-39463",
    "CVE-2024-39464",
    "CVE-2024-39465",
    "CVE-2024-39466",
    "CVE-2024-39467",
    "CVE-2024-39468",
    "CVE-2024-39469",
    "CVE-2024-39470",
    "CVE-2024-39471",
    "CVE-2024-39473",
    "CVE-2024-39474",
    "CVE-2024-39475",
    "CVE-2024-39478",
    "CVE-2024-39479",
    "CVE-2024-39480",
    "CVE-2024-39481",
    "CVE-2024-39483",
    "CVE-2024-39484",
    "CVE-2024-39485",
    "CVE-2024-39488",
    "CVE-2024-39489",
    "CVE-2024-39490",
    "CVE-2024-39491",
    "CVE-2024-39492",
    "CVE-2024-39493",
    "CVE-2024-39494",
    "CVE-2024-39495",
    "CVE-2024-39496",
    "CVE-2024-39497",
    "CVE-2024-39498",
    "CVE-2024-39499",
    "CVE-2024-39500",
    "CVE-2024-39501",
    "CVE-2024-39502",
    "CVE-2024-39503",
    "CVE-2024-39504",
    "CVE-2024-39505",
    "CVE-2024-39506",
    "CVE-2024-39507",
    "CVE-2024-39508",
    "CVE-2024-39509",
    "CVE-2024-39510",
    "CVE-2024-40899",
    "CVE-2024-40900",
    "CVE-2024-40901",
    "CVE-2024-40902",
    "CVE-2024-40903",
    "CVE-2024-40904",
    "CVE-2024-40905",
    "CVE-2024-40906",
    "CVE-2024-40908",
    "CVE-2024-40909",
    "CVE-2024-40910",
    "CVE-2024-40911",
    "CVE-2024-40912",
    "CVE-2024-40913",
    "CVE-2024-40914",
    "CVE-2024-40915",
    "CVE-2024-40916",
    "CVE-2024-40917",
    "CVE-2024-40918",
    "CVE-2024-40919",
    "CVE-2024-40920",
    "CVE-2024-40921",
    "CVE-2024-40922",
    "CVE-2024-40923",
    "CVE-2024-40924",
    "CVE-2024-40925",
    "CVE-2024-40926",
    "CVE-2024-40927",
    "CVE-2024-40928",
    "CVE-2024-40929",
    "CVE-2024-40930",
    "CVE-2024-40931",
    "CVE-2024-40932",
    "CVE-2024-40933",
    "CVE-2024-40934",
    "CVE-2024-40935",
    "CVE-2024-40936",
    "CVE-2024-40937",
    "CVE-2024-40938",
    "CVE-2024-40939",
    "CVE-2024-40940",
    "CVE-2024-40941",
    "CVE-2024-40942",
    "CVE-2024-40943",
    "CVE-2024-40944",
    "CVE-2024-40945",
    "CVE-2024-40947",
    "CVE-2024-40948",
    "CVE-2024-40949",
    "CVE-2024-40951",
    "CVE-2024-40952",
    "CVE-2024-40953",
    "CVE-2024-40954",
    "CVE-2024-40955",
    "CVE-2024-40956",
    "CVE-2024-40957",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40960",
    "CVE-2024-40961",
    "CVE-2024-40962",
    "CVE-2024-40963",
    "CVE-2024-40964",
    "CVE-2024-40965",
    "CVE-2024-40966",
    "CVE-2024-40967",
    "CVE-2024-40968",
    "CVE-2024-40969",
    "CVE-2024-40970",
    "CVE-2024-40971",
    "CVE-2024-40972",
    "CVE-2024-40973",
    "CVE-2024-40974",
    "CVE-2024-40975",
    "CVE-2024-40976",
    "CVE-2024-40977",
    "CVE-2024-40978",
    "CVE-2024-40979",
    "CVE-2024-40980",
    "CVE-2024-40981",
    "CVE-2024-40982",
    "CVE-2024-40983",
    "CVE-2024-40984",
    "CVE-2024-40985",
    "CVE-2024-40986",
    "CVE-2024-40987",
    "CVE-2024-40988",
    "CVE-2024-40989",
    "CVE-2024-40990",
    "CVE-2024-40992",
    "CVE-2024-40994",
    "CVE-2024-40995",
    "CVE-2024-40996",
    "CVE-2024-40997",
    "CVE-2024-40998",
    "CVE-2024-40999",
    "CVE-2024-41000",
    "CVE-2024-41001",
    "CVE-2024-41002",
    "CVE-2024-41003",
    "CVE-2024-41004",
    "CVE-2024-41005",
    "CVE-2024-41006",
    "CVE-2024-41040",
    "CVE-2024-42078",
    "CVE-2024-42148"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");
  script_xref(name:"USN", value:"7008-1");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel vulnerabilities (USN-7008-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-7008-1 advisory.

    Chenyuan Yang discovered that the CEC driver driver in the Linux kernel contained a use-after-free
    vulnerability. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2024-23848)

    It was discovered that the JFS file system contained an out-of-bounds read vulnerability when printing
    xattr debug information. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2024-40902)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - MIPS architecture;

    - PA-RISC architecture;

    - PowerPC architecture;

    - RISC-V architecture;

    - User-Mode Linux (UML);

    - x86 architecture;

    - Block layer subsystem;

    - ACPI drivers;

    - Drivers core;

    - Null block device driver;

    - Character device driver;

    - TPM device driver;

    - Clock framework and drivers;

    - CPU frequency scaling framework;

    - Hardware crypto device drivers;

    - CXL (Compute Express Link) drivers;

    - Buffer Sharing and Synchronization framework;

    - DMA engine subsystem;

    - EFI core;

    - FPGA Framework;

    - GPU drivers;

    - Greybus drivers;

    - HID subsystem;

    - HW tracing;

    - I2C subsystem;

    - IIO subsystem;

    - InfiniBand drivers;

    - Input Device (Mouse) drivers;

    - Mailbox framework;

    - Media drivers;

    - Microchip PCI driver;

    - VMware VMCI Driver;

    - MMC subsystem;

    - Network drivers;

    - PCI subsystem;

    - x86 platform drivers;

    - PTP clock framework;

    - S/390 drivers;

    - SCSI drivers;

    - SoundWire subsystem;

    - Sonic Silicon Backplane drivers;

    - Greybus lights staging drivers;

    - Thermal drivers;

    - TTY drivers;

    - USB subsystem;

    - VFIO drivers;

    - Framebuffer layer;

    - Watchdog drivers;

    - 9P distributed file system;

    - BTRFS file system;

    - File systems infrastructure;

    - Ext4 file system;

    - F2FS file system;

    - JFS file system;

    - Network file system server daemon;

    - NILFS2 file system;

    - NTFS3 file system;

    - SMB network file system;

    - Tracing file system;

    - IOMMU subsystem;

    - Tracing infrastructure;

    - io_uring subsystem;

    - Core kernel;

    - BPF subsystem;

    - Kernel debugger infrastructure;

    - DMA mapping infrastructure;

    - IRQ subsystem;

    - Memory management;

    - 9P file system network protocol;

    - Amateur Radio drivers;

    - B.A.T.M.A.N. meshing protocol;

    - Ethernet bridge;

    - Networking core;

    - Ethtool driver;

    - IPv4 networking;

    - IPv6 networking;

    - MAC80211 subsystem;

    - Multipath TCP;

    - Netfilter;

    - NET/ROM layer;

    - NFC subsystem;

    - Network traffic control;

    - Sun RPC protocol;

    - TIPC protocol;

    - TLS protocol;

    - Unix domain sockets;

    - Wireless networking;

    - XFRM subsystem;

    - AppArmor security module;

    - Integrity Measurement Architecture(IMA) framework;

    - Landlock security;

    - Linux Security Modules (LSM) Framework;

    - SELinux security module;

    - Simplified Mandatory Access Control Kernel framework;

    - ALSA framework;

    - HD-audio driver;

    - SOF drivers;

    - KVM core; (CVE-2024-38623, CVE-2024-38662, CVE-2024-39484, CVE-2024-42148, CVE-2024-39493,
    CVE-2024-38637, CVE-2024-40962, CVE-2024-36281, CVE-2024-40922, CVE-2024-40958, CVE-2024-40920,
    CVE-2024-40986, CVE-2024-40929, CVE-2024-40967, CVE-2024-39296, CVE-2024-40900, CVE-2024-40995,
    CVE-2024-40974, CVE-2024-40942, CVE-2024-39464, CVE-2024-40916, CVE-2024-40952, CVE-2024-40997,
    CVE-2024-41004, CVE-2024-40970, CVE-2024-40911, CVE-2024-40972, CVE-2024-36477, CVE-2024-40996,
    CVE-2024-40988, CVE-2024-38619, CVE-2024-40998, CVE-2024-38627, CVE-2024-36971, CVE-2024-37021,
    CVE-2024-40989, CVE-2024-40947, CVE-2024-40957, CVE-2024-39508, CVE-2024-41005, CVE-2024-40931,
    CVE-2024-34777, CVE-2024-38633, CVE-2024-38663, CVE-2024-36288, CVE-2024-40955, CVE-2024-40973,
    CVE-2024-39483, CVE-2024-38388, CVE-2024-40976, CVE-2024-38622, CVE-2024-40915, CVE-2024-38661,
    CVE-2024-38306, CVE-2024-39507, CVE-2024-38659, CVE-2024-40980, CVE-2024-39301, CVE-2024-40945,
    CVE-2024-39461, CVE-2024-40948, CVE-2024-39465, CVE-2024-38667, CVE-2024-39498, CVE-2024-39470,
    CVE-2024-38629, CVE-2024-40984, CVE-2024-38381, CVE-2024-40903, CVE-2024-38636, CVE-2024-36478,
    CVE-2023-52884, CVE-2024-40906, CVE-2024-39371, CVE-2024-38384, CVE-2024-40938, CVE-2024-36978,
    CVE-2024-39502, CVE-2024-39291, CVE-2024-39473, CVE-2024-40956, CVE-2024-38618, CVE-2024-40992,
    CVE-2024-40944, CVE-2024-39495, CVE-2024-39494, CVE-2024-38632, CVE-2024-38390, CVE-2024-39497,
    CVE-2024-40899, CVE-2024-40939, CVE-2024-36481, CVE-2024-40977, CVE-2024-40961, CVE-2024-33847,
    CVE-2024-40963, CVE-2024-39276, CVE-2024-40902, CVE-2024-40971, CVE-2024-39485, CVE-2024-40930,
    CVE-2024-40985, CVE-2024-39501, CVE-2024-40960, CVE-2024-39503, CVE-2024-40909, CVE-2024-36973,
    CVE-2024-36489, CVE-2024-40928, CVE-2024-34027, CVE-2024-40914, CVE-2024-40925, CVE-2024-39500,
    CVE-2024-39292, CVE-2024-40987, CVE-2024-39480, CVE-2024-40934, CVE-2024-36270, CVE-2024-38780,
    CVE-2024-39479, CVE-2024-39462, CVE-2024-40966, CVE-2024-39510, CVE-2024-39471, CVE-2024-39505,
    CVE-2024-37078, CVE-2024-40913, CVE-2024-37356, CVE-2024-38624, CVE-2024-40917, CVE-2024-39506,
    CVE-2024-40943, CVE-2024-38625, CVE-2024-38664, CVE-2024-40901, CVE-2024-40964, CVE-2024-40924,
    CVE-2024-40918, CVE-2024-36974, CVE-2022-48772, CVE-2024-39509, CVE-2024-38385, CVE-2024-40994,
    CVE-2024-39469, CVE-2024-40905, CVE-2024-35247, CVE-2024-41006, CVE-2024-40965, CVE-2024-40932,
    CVE-2024-39491, CVE-2024-39499, CVE-2024-40908, CVE-2024-36972, CVE-2024-37026, CVE-2024-40968,
    CVE-2024-36244, CVE-2024-39468, CVE-2024-39489, CVE-2024-33621, CVE-2024-40951, CVE-2024-39481,
    CVE-2024-40959, CVE-2024-40935, CVE-2024-40927, CVE-2024-40912, CVE-2024-36479, CVE-2024-39467,
    CVE-2024-34030, CVE-2024-41003, CVE-2024-40936, CVE-2024-39474, CVE-2024-40969, CVE-2024-40904,
    CVE-2024-40937, CVE-2024-40978, CVE-2024-40983, CVE-2024-40910, CVE-2024-39466, CVE-2024-40949,
    CVE-2024-39478, CVE-2024-40999, CVE-2024-33619, CVE-2024-38621, CVE-2024-40981, CVE-2024-39475,
    CVE-2024-40954, CVE-2024-41000, CVE-2024-39496, CVE-2024-40926, CVE-2024-41040, CVE-2024-39298,
    CVE-2024-38635, CVE-2024-39492, CVE-2024-38628, CVE-2024-39504, CVE-2024-42078, CVE-2024-41001,
    CVE-2024-39463, CVE-2024-36286, CVE-2024-36484, CVE-2024-40990, CVE-2024-31076, CVE-2024-38630,
    CVE-2024-40979, CVE-2024-36015, CVE-2024-40923, CVE-2024-40921, CVE-2024-41002, CVE-2024-40940,
    CVE-2024-40975, CVE-2024-40953, CVE-2024-40933, CVE-2024-37354, CVE-2024-40982, CVE-2024-38634,
    CVE-2024-39490, CVE-2024-39277, CVE-2024-39488, CVE-2024-40941, CVE-2024-32936, CVE-2024-40919)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7008-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42148");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-44-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-44-lowlatency-64k");
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
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '22.04': {
    '6.8.0': {
      'lowlatency': '6.8.0-44',
      'lowlatency-64k': '6.8.0-44'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7008-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-48772', 'CVE-2023-52884', 'CVE-2024-23848', 'CVE-2024-31076', 'CVE-2024-32936', 'CVE-2024-33619', 'CVE-2024-33621', 'CVE-2024-33847', 'CVE-2024-34027', 'CVE-2024-34030', 'CVE-2024-34777', 'CVE-2024-35247', 'CVE-2024-36015', 'CVE-2024-36244', 'CVE-2024-36270', 'CVE-2024-36281', 'CVE-2024-36286', 'CVE-2024-36288', 'CVE-2024-36477', 'CVE-2024-36478', 'CVE-2024-36479', 'CVE-2024-36481', 'CVE-2024-36484', 'CVE-2024-36489', 'CVE-2024-36971', 'CVE-2024-36972', 'CVE-2024-36973', 'CVE-2024-36974', 'CVE-2024-36978', 'CVE-2024-37021', 'CVE-2024-37026', 'CVE-2024-37078', 'CVE-2024-37354', 'CVE-2024-37356', 'CVE-2024-38306', 'CVE-2024-38381', 'CVE-2024-38384', 'CVE-2024-38385', 'CVE-2024-38388', 'CVE-2024-38390', 'CVE-2024-38618', 'CVE-2024-38619', 'CVE-2024-38621', 'CVE-2024-38622', 'CVE-2024-38623', 'CVE-2024-38624', 'CVE-2024-38625', 'CVE-2024-38627', 'CVE-2024-38628', 'CVE-2024-38629', 'CVE-2024-38630', 'CVE-2024-38632', 'CVE-2024-38633', 'CVE-2024-38634', 'CVE-2024-38635', 'CVE-2024-38636', 'CVE-2024-38637', 'CVE-2024-38659', 'CVE-2024-38661', 'CVE-2024-38662', 'CVE-2024-38663', 'CVE-2024-38664', 'CVE-2024-38667', 'CVE-2024-38780', 'CVE-2024-39276', 'CVE-2024-39277', 'CVE-2024-39291', 'CVE-2024-39292', 'CVE-2024-39296', 'CVE-2024-39298', 'CVE-2024-39301', 'CVE-2024-39371', 'CVE-2024-39461', 'CVE-2024-39462', 'CVE-2024-39463', 'CVE-2024-39464', 'CVE-2024-39465', 'CVE-2024-39466', 'CVE-2024-39467', 'CVE-2024-39468', 'CVE-2024-39469', 'CVE-2024-39470', 'CVE-2024-39471', 'CVE-2024-39473', 'CVE-2024-39474', 'CVE-2024-39475', 'CVE-2024-39478', 'CVE-2024-39479', 'CVE-2024-39480', 'CVE-2024-39481', 'CVE-2024-39483', 'CVE-2024-39484', 'CVE-2024-39485', 'CVE-2024-39488', 'CVE-2024-39489', 'CVE-2024-39490', 'CVE-2024-39491', 'CVE-2024-39492', 'CVE-2024-39493', 'CVE-2024-39494', 'CVE-2024-39495', 'CVE-2024-39496', 'CVE-2024-39497', 'CVE-2024-39498', 'CVE-2024-39499', 'CVE-2024-39500', 'CVE-2024-39501', 'CVE-2024-39502', 'CVE-2024-39503', 'CVE-2024-39504', 'CVE-2024-39505', 'CVE-2024-39506', 'CVE-2024-39507', 'CVE-2024-39508', 'CVE-2024-39509', 'CVE-2024-39510', 'CVE-2024-40899', 'CVE-2024-40900', 'CVE-2024-40901', 'CVE-2024-40902', 'CVE-2024-40903', 'CVE-2024-40904', 'CVE-2024-40905', 'CVE-2024-40906', 'CVE-2024-40908', 'CVE-2024-40909', 'CVE-2024-40910', 'CVE-2024-40911', 'CVE-2024-40912', 'CVE-2024-40913', 'CVE-2024-40914', 'CVE-2024-40915', 'CVE-2024-40916', 'CVE-2024-40917', 'CVE-2024-40918', 'CVE-2024-40919', 'CVE-2024-40920', 'CVE-2024-40921', 'CVE-2024-40922', 'CVE-2024-40923', 'CVE-2024-40924', 'CVE-2024-40925', 'CVE-2024-40926', 'CVE-2024-40927', 'CVE-2024-40928', 'CVE-2024-40929', 'CVE-2024-40930', 'CVE-2024-40931', 'CVE-2024-40932', 'CVE-2024-40933', 'CVE-2024-40934', 'CVE-2024-40935', 'CVE-2024-40936', 'CVE-2024-40937', 'CVE-2024-40938', 'CVE-2024-40939', 'CVE-2024-40940', 'CVE-2024-40941', 'CVE-2024-40942', 'CVE-2024-40943', 'CVE-2024-40944', 'CVE-2024-40945', 'CVE-2024-40947', 'CVE-2024-40948', 'CVE-2024-40949', 'CVE-2024-40951', 'CVE-2024-40952', 'CVE-2024-40953', 'CVE-2024-40954', 'CVE-2024-40955', 'CVE-2024-40956', 'CVE-2024-40957', 'CVE-2024-40958', 'CVE-2024-40959', 'CVE-2024-40960', 'CVE-2024-40961', 'CVE-2024-40962', 'CVE-2024-40963', 'CVE-2024-40964', 'CVE-2024-40965', 'CVE-2024-40966', 'CVE-2024-40967', 'CVE-2024-40968', 'CVE-2024-40969', 'CVE-2024-40970', 'CVE-2024-40971', 'CVE-2024-40972', 'CVE-2024-40973', 'CVE-2024-40974', 'CVE-2024-40975', 'CVE-2024-40976', 'CVE-2024-40977', 'CVE-2024-40978', 'CVE-2024-40979', 'CVE-2024-40980', 'CVE-2024-40981', 'CVE-2024-40982', 'CVE-2024-40983', 'CVE-2024-40984', 'CVE-2024-40985', 'CVE-2024-40986', 'CVE-2024-40987', 'CVE-2024-40988', 'CVE-2024-40989', 'CVE-2024-40990', 'CVE-2024-40992', 'CVE-2024-40994', 'CVE-2024-40995', 'CVE-2024-40996', 'CVE-2024-40997', 'CVE-2024-40998', 'CVE-2024-40999', 'CVE-2024-41000', 'CVE-2024-41001', 'CVE-2024-41002', 'CVE-2024-41003', 'CVE-2024-41004', 'CVE-2024-41005', 'CVE-2024-41006', 'CVE-2024-41040', 'CVE-2024-42078', 'CVE-2024-42148');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7008-1');
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
