#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7088-5. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211362);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2021-47212",
    "CVE-2022-36402",
    "CVE-2023-52531",
    "CVE-2023-52614",
    "CVE-2023-52918",
    "CVE-2024-26607",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26668",
    "CVE-2024-26669",
    "CVE-2024-26800",
    "CVE-2024-26885",
    "CVE-2024-26891",
    "CVE-2024-27051",
    "CVE-2024-35848",
    "CVE-2024-36484",
    "CVE-2024-38602",
    "CVE-2024-38611",
    "CVE-2024-40929",
    "CVE-2024-41011",
    "CVE-2024-41012",
    "CVE-2024-41015",
    "CVE-2024-41017",
    "CVE-2024-41020",
    "CVE-2024-41022",
    "CVE-2024-41042",
    "CVE-2024-41059",
    "CVE-2024-41063",
    "CVE-2024-41064",
    "CVE-2024-41065",
    "CVE-2024-41068",
    "CVE-2024-41070",
    "CVE-2024-41071",
    "CVE-2024-41072",
    "CVE-2024-41073",
    "CVE-2024-41081",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-41098",
    "CVE-2024-42131",
    "CVE-2024-42229",
    "CVE-2024-42244",
    "CVE-2024-42246",
    "CVE-2024-42259",
    "CVE-2024-42265",
    "CVE-2024-42271",
    "CVE-2024-42276",
    "CVE-2024-42280",
    "CVE-2024-42281",
    "CVE-2024-42283",
    "CVE-2024-42284",
    "CVE-2024-42285",
    "CVE-2024-42286",
    "CVE-2024-42287",
    "CVE-2024-42288",
    "CVE-2024-42289",
    "CVE-2024-42290",
    "CVE-2024-42292",
    "CVE-2024-42295",
    "CVE-2024-42297",
    "CVE-2024-42301",
    "CVE-2024-42304",
    "CVE-2024-42305",
    "CVE-2024-42306",
    "CVE-2024-42309",
    "CVE-2024-42310",
    "CVE-2024-42311",
    "CVE-2024-42313",
    "CVE-2024-43829",
    "CVE-2024-43830",
    "CVE-2024-43835",
    "CVE-2024-43839",
    "CVE-2024-43841",
    "CVE-2024-43846",
    "CVE-2024-43853",
    "CVE-2024-43854",
    "CVE-2024-43856",
    "CVE-2024-43858",
    "CVE-2024-43860",
    "CVE-2024-43861",
    "CVE-2024-43867",
    "CVE-2024-43871",
    "CVE-2024-43879",
    "CVE-2024-43880",
    "CVE-2024-43882",
    "CVE-2024-43883",
    "CVE-2024-43884",
    "CVE-2024-43890",
    "CVE-2024-43893",
    "CVE-2024-43894",
    "CVE-2024-43908",
    "CVE-2024-43914",
    "CVE-2024-44935",
    "CVE-2024-44944",
    "CVE-2024-44946",
    "CVE-2024-44947",
    "CVE-2024-44948",
    "CVE-2024-44952",
    "CVE-2024-44954",
    "CVE-2024-44960",
    "CVE-2024-44965",
    "CVE-2024-44969",
    "CVE-2024-44987",
    "CVE-2024-44988",
    "CVE-2024-44995",
    "CVE-2024-44998",
    "CVE-2024-44999",
    "CVE-2024-45003",
    "CVE-2024-45006",
    "CVE-2024-45008",
    "CVE-2024-45021",
    "CVE-2024-45025",
    "CVE-2024-45026",
    "CVE-2024-45028",
    "CVE-2024-46673",
    "CVE-2024-46675",
    "CVE-2024-46676",
    "CVE-2024-46677",
    "CVE-2024-46679",
    "CVE-2024-46685",
    "CVE-2024-46689",
    "CVE-2024-46714",
    "CVE-2024-46719",
    "CVE-2024-46721",
    "CVE-2024-46722",
    "CVE-2024-46723",
    "CVE-2024-46737",
    "CVE-2024-46738",
    "CVE-2024-46739",
    "CVE-2024-46740",
    "CVE-2024-46743",
    "CVE-2024-46744",
    "CVE-2024-46745",
    "CVE-2024-46747",
    "CVE-2024-46750",
    "CVE-2024-46755",
    "CVE-2024-46756",
    "CVE-2024-46757",
    "CVE-2024-46758",
    "CVE-2024-46759",
    "CVE-2024-46761",
    "CVE-2024-46771",
    "CVE-2024-46777",
    "CVE-2024-46780",
    "CVE-2024-46781",
    "CVE-2024-46782",
    "CVE-2024-46783",
    "CVE-2024-46798",
    "CVE-2024-46800",
    "CVE-2024-46815",
    "CVE-2024-46817",
    "CVE-2024-46818",
    "CVE-2024-46822",
    "CVE-2024-46828",
    "CVE-2024-46829",
    "CVE-2024-46840",
    "CVE-2024-46844",
    "CVE-2024-47659",
    "CVE-2024-47663",
    "CVE-2024-47667",
    "CVE-2024-47668",
    "CVE-2024-47669"
  );
  script_xref(name:"USN", value:"7088-5");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-7088-5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-7088-5 advisory.

    Ziming Zhang discovered that the VMware Virtual GPU DRM driver in the Linux kernel contained an integer
    overflow vulnerability. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2022-36402)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - PowerPC architecture;

    - User-Mode Linux (UML);

    - x86 architecture;

    - Block layer subsystem;

    - Cryptographic API;

    - Android drivers;

    - Serial ATA and Parallel ATA drivers;

    - ATM drivers;

    - Drivers core;

    - CPU frequency scaling framework;

    - Device frequency scaling framework;

    - GPU drivers;

    - HID subsystem;

    - Hardware monitoring drivers;

    - InfiniBand drivers;

    - Input Device core drivers;

    - Input Device (Miscellaneous) drivers;

    - IOMMU subsystem;

    - IRQ chip drivers;

    - ISDN/mISDN subsystem;

    - LED subsystem;

    - Multiple devices driver;

    - Media drivers;

    - EEPROM drivers;

    - VMware VMCI Driver;

    - MMC subsystem;

    - Network drivers;

    - Near Field Communication (NFC) drivers;

    - NVME drivers;

    - Device tree and open firmware driver;

    - Parport drivers;

    - PCI subsystem;

    - Pin controllers subsystem;

    - Remote Processor subsystem;

    - S/390 drivers;

    - SCSI drivers;

    - QCOM SoC drivers;

    - Direct Digital Synthesis drivers;

    - TTY drivers;

    - Userspace I/O drivers;

    - DesignWare USB3 driver;

    - USB Gadget drivers;

    - USB Host Controller drivers;

    - USB Serial drivers;

    - USB Type-C Connector System Software Interface driver;

    - USB over IP driver;

    - BTRFS file system;

    - File systems infrastructure;

    - Ext4 file system;

    - F2FS file system;

    - JFS file system;

    - NILFS2 file system;

    - BPF subsystem;

    - Core kernel;

    - DMA mapping infrastructure;

    - Tracing infrastructure;

    - Radix Tree data structure library;

    - Kernel userspace event delivery library;

    - Objagg library;

    - Memory management;

    - Amateur Radio drivers;

    - Bluetooth subsystem;

    - CAN network layer;

    - Networking core;

    - Ethtool driver;

    - IPv4 networking;

    - IPv6 networking;

    - IUCV driver;

    - KCM (Kernel Connection Multiplexor) sockets driver;

    - MAC80211 subsystem;

    - Netfilter;

    - Network traffic control;

    - SCTP protocol;

    - Sun RPC protocol;

    - TIPC protocol;

    - TLS protocol;

    - Wireless networking;

    - AppArmor security module;

    - Simplified Mandatory Access Control Kernel framework;

    - SoC audio core drivers;

    - USB sound devices; (CVE-2024-42289, CVE-2024-26640, CVE-2024-42246, CVE-2024-43914, CVE-2024-46744,
    CVE-2024-45026, CVE-2024-41071, CVE-2024-43893, CVE-2024-46689, CVE-2024-41073, CVE-2024-42292,
    CVE-2024-43884, CVE-2024-42301, CVE-2024-43856, CVE-2024-46756, CVE-2024-46759, CVE-2024-27051,
    CVE-2024-26668, CVE-2024-46840, CVE-2024-42306, CVE-2024-41042, CVE-2024-45006, CVE-2024-42309,
    CVE-2024-26891, CVE-2024-42283, CVE-2024-46782, CVE-2024-44948, CVE-2024-43839, CVE-2024-47667,
    CVE-2024-44965, CVE-2024-42284, CVE-2024-44987, CVE-2024-46777, CVE-2024-41017, CVE-2024-46722,
    CVE-2024-41015, CVE-2024-46817, CVE-2024-46740, CVE-2024-43894, CVE-2024-26800, CVE-2024-45003,
    CVE-2024-46822, CVE-2024-26641, CVE-2024-44960, CVE-2024-44935, CVE-2024-42229, CVE-2024-42285,
    CVE-2024-44988, CVE-2024-46829, CVE-2024-41012, CVE-2024-46750, CVE-2024-43835, CVE-2024-43883,
    CVE-2024-43882, CVE-2024-46844, CVE-2024-41011, CVE-2024-44999, CVE-2024-46757, CVE-2024-42131,
    CVE-2024-46714, CVE-2024-41081, CVE-2024-45021, CVE-2024-46747, CVE-2024-46673, CVE-2024-46737,
    CVE-2024-43841, CVE-2024-42304, CVE-2024-45008, CVE-2024-42259, CVE-2024-42276, CVE-2024-46685,
    CVE-2024-46743, CVE-2023-52614, CVE-2024-42313, CVE-2024-41090, CVE-2024-46677, CVE-2024-43861,
    CVE-2024-42288, CVE-2024-43890, CVE-2024-41063, CVE-2024-43860, CVE-2024-47669, CVE-2024-42305,
    CVE-2024-43879, CVE-2024-42281, CVE-2024-46798, CVE-2024-42280, CVE-2024-42297, CVE-2024-42310,
    CVE-2024-44947, CVE-2024-40929, CVE-2024-41068, CVE-2024-42244, CVE-2024-41059, CVE-2024-47659,
    CVE-2024-43858, CVE-2024-41020, CVE-2024-41064, CVE-2023-52531, CVE-2024-41022, CVE-2024-46723,
    CVE-2024-42311, CVE-2024-44969, CVE-2024-45025, CVE-2024-44946, CVE-2024-46755, CVE-2024-46815,
    CVE-2024-46761, CVE-2024-43867, CVE-2024-41070, CVE-2024-43880, CVE-2024-47663, CVE-2024-44944,
    CVE-2024-45028, CVE-2024-43908, CVE-2024-46783, CVE-2024-43853, CVE-2024-41091, CVE-2024-46719,
    CVE-2024-43871, CVE-2024-36484, CVE-2024-46771, CVE-2024-42265, CVE-2024-42286, CVE-2024-43854,
    CVE-2024-41072, CVE-2024-43830, CVE-2024-46721, CVE-2024-44995, CVE-2024-46828, CVE-2024-46780,
    CVE-2024-46739, CVE-2024-46676, CVE-2024-47668, CVE-2024-42287, CVE-2023-52918, CVE-2024-46745,
    CVE-2024-35848, CVE-2024-42290, CVE-2024-41065, CVE-2024-42271, CVE-2024-38611, CVE-2024-41098,
    CVE-2024-43846, CVE-2024-26885, CVE-2021-47212, CVE-2024-46781, CVE-2024-26607, CVE-2024-26669,
    CVE-2024-44954, CVE-2024-42295, CVE-2024-46818, CVE-2024-44952, CVE-2024-46738, CVE-2024-44998,
    CVE-2024-46675, CVE-2024-43829, CVE-2024-46758, CVE-2024-38602, CVE-2024-46800, CVE-2024-46679)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7088-5");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47659");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1119-raspi");
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
      'raspi': '5.4.0-1119'
    }
  },
  '20.04': {
    '5.4.0': {
      'raspi': '5.4.0-1119'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7088-5');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-47212', 'CVE-2022-36402', 'CVE-2023-52531', 'CVE-2023-52614', 'CVE-2023-52918', 'CVE-2024-26607', 'CVE-2024-26640', 'CVE-2024-26641', 'CVE-2024-26668', 'CVE-2024-26669', 'CVE-2024-26800', 'CVE-2024-26885', 'CVE-2024-26891', 'CVE-2024-27051', 'CVE-2024-35848', 'CVE-2024-36484', 'CVE-2024-38602', 'CVE-2024-38611', 'CVE-2024-40929', 'CVE-2024-41011', 'CVE-2024-41012', 'CVE-2024-41015', 'CVE-2024-41017', 'CVE-2024-41020', 'CVE-2024-41022', 'CVE-2024-41042', 'CVE-2024-41059', 'CVE-2024-41063', 'CVE-2024-41064', 'CVE-2024-41065', 'CVE-2024-41068', 'CVE-2024-41070', 'CVE-2024-41071', 'CVE-2024-41072', 'CVE-2024-41073', 'CVE-2024-41081', 'CVE-2024-41090', 'CVE-2024-41091', 'CVE-2024-41098', 'CVE-2024-42131', 'CVE-2024-42229', 'CVE-2024-42244', 'CVE-2024-42246', 'CVE-2024-42259', 'CVE-2024-42265', 'CVE-2024-42271', 'CVE-2024-42276', 'CVE-2024-42280', 'CVE-2024-42281', 'CVE-2024-42283', 'CVE-2024-42284', 'CVE-2024-42285', 'CVE-2024-42286', 'CVE-2024-42287', 'CVE-2024-42288', 'CVE-2024-42289', 'CVE-2024-42290', 'CVE-2024-42292', 'CVE-2024-42295', 'CVE-2024-42297', 'CVE-2024-42301', 'CVE-2024-42304', 'CVE-2024-42305', 'CVE-2024-42306', 'CVE-2024-42309', 'CVE-2024-42310', 'CVE-2024-42311', 'CVE-2024-42313', 'CVE-2024-43829', 'CVE-2024-43830', 'CVE-2024-43835', 'CVE-2024-43839', 'CVE-2024-43841', 'CVE-2024-43846', 'CVE-2024-43853', 'CVE-2024-43854', 'CVE-2024-43856', 'CVE-2024-43858', 'CVE-2024-43860', 'CVE-2024-43861', 'CVE-2024-43867', 'CVE-2024-43871', 'CVE-2024-43879', 'CVE-2024-43880', 'CVE-2024-43882', 'CVE-2024-43883', 'CVE-2024-43884', 'CVE-2024-43890', 'CVE-2024-43893', 'CVE-2024-43894', 'CVE-2024-43908', 'CVE-2024-43914', 'CVE-2024-44935', 'CVE-2024-44944', 'CVE-2024-44946', 'CVE-2024-44947', 'CVE-2024-44948', 'CVE-2024-44952', 'CVE-2024-44954', 'CVE-2024-44960', 'CVE-2024-44965', 'CVE-2024-44969', 'CVE-2024-44987', 'CVE-2024-44988', 'CVE-2024-44995', 'CVE-2024-44998', 'CVE-2024-44999', 'CVE-2024-45003', 'CVE-2024-45006', 'CVE-2024-45008', 'CVE-2024-45021', 'CVE-2024-45025', 'CVE-2024-45026', 'CVE-2024-45028', 'CVE-2024-46673', 'CVE-2024-46675', 'CVE-2024-46676', 'CVE-2024-46677', 'CVE-2024-46679', 'CVE-2024-46685', 'CVE-2024-46689', 'CVE-2024-46714', 'CVE-2024-46719', 'CVE-2024-46721', 'CVE-2024-46722', 'CVE-2024-46723', 'CVE-2024-46737', 'CVE-2024-46738', 'CVE-2024-46739', 'CVE-2024-46740', 'CVE-2024-46743', 'CVE-2024-46744', 'CVE-2024-46745', 'CVE-2024-46747', 'CVE-2024-46750', 'CVE-2024-46755', 'CVE-2024-46756', 'CVE-2024-46757', 'CVE-2024-46758', 'CVE-2024-46759', 'CVE-2024-46761', 'CVE-2024-46771', 'CVE-2024-46777', 'CVE-2024-46780', 'CVE-2024-46781', 'CVE-2024-46782', 'CVE-2024-46783', 'CVE-2024-46798', 'CVE-2024-46800', 'CVE-2024-46815', 'CVE-2024-46817', 'CVE-2024-46818', 'CVE-2024-46822', 'CVE-2024-46828', 'CVE-2024-46829', 'CVE-2024-46840', 'CVE-2024-46844', 'CVE-2024-47659', 'CVE-2024-47663', 'CVE-2024-47667', 'CVE-2024-47668', 'CVE-2024-47669');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7088-5');
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
