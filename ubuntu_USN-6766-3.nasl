#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6766-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197517);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/15");

  script_cve_id(
    "CVE-2023-52435",
    "CVE-2023-52486",
    "CVE-2023-52489",
    "CVE-2023-52491",
    "CVE-2023-52492",
    "CVE-2023-52493",
    "CVE-2023-52494",
    "CVE-2023-52498",
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
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2023-52627",
    "CVE-2023-52631",
    "CVE-2023-52633",
    "CVE-2023-52635",
    "CVE-2023-52637",
    "CVE-2023-52638",
    "CVE-2023-52642",
    "CVE-2023-52643",
    "CVE-2024-1151",
    "CVE-2024-2201",
    "CVE-2024-23849",
    "CVE-2024-26592",
    "CVE-2024-26593",
    "CVE-2024-26594",
    "CVE-2024-26600",
    "CVE-2024-26602",
    "CVE-2024-26606",
    "CVE-2024-26608",
    "CVE-2024-26610",
    "CVE-2024-26614",
    "CVE-2024-26615",
    "CVE-2024-26625",
    "CVE-2024-26627",
    "CVE-2024-26635",
    "CVE-2024-26636",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26644",
    "CVE-2024-26645",
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
    "CVE-2024-26808",
    "CVE-2024-26825",
    "CVE-2024-26826",
    "CVE-2024-26829",
    "CVE-2024-26910",
    "CVE-2024-26916",
    "CVE-2024-26920"
  );
  script_xref(name:"USN", value:"6766-3");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : Linux kernel (AWS) vulnerabilities (USN-6766-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6766-3 advisory.

    It was discovered that the Open vSwitch implementation in the Linux kernel could overflow its stack during
    recursive action operations under certain conditions. A local attacker could use this to cause a denial of
    service (system crash). (CVE-2024-1151)

    Sander Wiebing, Alvise de Faveri Tron, Herbert Bos, and Cristiano Giuffrida discovered that the Linux
    kernel mitigations for the initial Branch History Injection vulnerability (CVE-2022-0001) were
    insufficient for Intel processors. A local attacker could potentially use this to expose sensitive
    information. (CVE-2024-2201)

    Chenyuan Yang discovered that the RDS Protocol implementation in the Linux kernel contained an out-of-
    bounds read vulnerability. An attacker could use this to possibly cause a denial of service (system
    crash). (CVE-2024-23849)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - PowerPC architecture;

    - S390 architecture;

    - Core kernel;

    - Block layer subsystem;

    - Android drivers;

    - Power management core;

    - Bus devices;

    - Hardware random number generator core;

    - Cryptographic API;

    - Device frequency;

    - DMA engine subsystem;

    - ARM SCMI message protocol;

    - GPU drivers;

    - HID subsystem;

    - Hardware monitoring drivers;

    - I2C subsystem;

    - IIO ADC drivers;

    - IIO subsystem;

    - IIO Magnetometer sensors drivers;

    - InfiniBand drivers;

    - Media drivers;

    - Network drivers;

    - PCI driver for MicroSemi Switchtec;

    - PHY drivers;

    - SCSI drivers;

    - DesignWare USB3 driver;

    - BTRFS file system;

    - Ceph distributed file system;

    - Ext4 file system;

    - F2FS file system;

    - JFS file system;

    - NILFS2 file system;

    - NTFS3 file system;

    - Pstore file system;

    - SMB network file system;

    - Memory management;

    - CAN network layer;

    - Networking core;

    - HSR network protocol;

    - IPv4 networking;

    - IPv6 networking;

    - Logical Link layer;

    - Multipath TCP;

    - Netfilter;

    - NFC subsystem;

    - SMC sockets;

    - Sun RPC protocol;

    - TIPC protocol;

    - Unix domain sockets;

    - Realtek audio codecs; (CVE-2023-52594, CVE-2023-52601, CVE-2024-26826, CVE-2023-52622, CVE-2024-26665,
    CVE-2023-52493, CVE-2023-52633, CVE-2024-26684, CVE-2024-26663, CVE-2023-52618, CVE-2023-52588,
    CVE-2023-52637, CVE-2024-26825, CVE-2023-52606, CVE-2024-26594, CVE-2024-26625, CVE-2024-26720,
    CVE-2024-26614, CVE-2023-52627, CVE-2023-52602, CVE-2024-26673, CVE-2024-26685, CVE-2023-52638,
    CVE-2023-52498, CVE-2023-52619, CVE-2024-26910, CVE-2024-26689, CVE-2023-52583, CVE-2024-26676,
    CVE-2024-26671, CVE-2024-26704, CVE-2024-26608, CVE-2024-26610, CVE-2024-26592, CVE-2023-52599,
    CVE-2023-52595, CVE-2024-26660, CVE-2023-52617, CVE-2024-26645, CVE-2023-52486, CVE-2023-52631,
    CVE-2023-52607, CVE-2023-52608, CVE-2024-26722, CVE-2024-26615, CVE-2023-52615, CVE-2024-26636,
    CVE-2023-52642, CVE-2023-52587, CVE-2024-26712, CVE-2024-26675, CVE-2023-52614, CVE-2024-26606,
    CVE-2024-26916, CVE-2024-26600, CVE-2024-26679, CVE-2024-26829, CVE-2024-26641, CVE-2023-52623,
    CVE-2024-26627, CVE-2024-26696, CVE-2024-26640, CVE-2024-26635, CVE-2023-52491, CVE-2024-26664,
    CVE-2024-26602, CVE-2023-52604, CVE-2024-26717, CVE-2023-52643, CVE-2024-26593, CVE-2023-52598,
    CVE-2024-26668, CVE-2023-52435, CVE-2023-52597, CVE-2024-26715, CVE-2024-26707, CVE-2023-52635,
    CVE-2024-26695, CVE-2024-26698, CVE-2023-52494, CVE-2024-26920, CVE-2024-26808, CVE-2023-52616,
    CVE-2023-52492, CVE-2024-26702, CVE-2024-26644, CVE-2023-52489, CVE-2024-26697)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6766-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26704");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1061-aws");
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
if (! ('20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '20.04': {
    '5.15.0': {
      'aws': '5.15.0-1061'
    }
  },
  '22.04': {
    '5.15.0': {
      'aws': '5.15.0-1061'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6766-3');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-52435', 'CVE-2023-52486', 'CVE-2023-52489', 'CVE-2023-52491', 'CVE-2023-52492', 'CVE-2023-52493', 'CVE-2023-52494', 'CVE-2023-52498', 'CVE-2023-52583', 'CVE-2023-52587', 'CVE-2023-52588', 'CVE-2023-52594', 'CVE-2023-52595', 'CVE-2023-52597', 'CVE-2023-52598', 'CVE-2023-52599', 'CVE-2023-52601', 'CVE-2023-52602', 'CVE-2023-52604', 'CVE-2023-52606', 'CVE-2023-52607', 'CVE-2023-52608', 'CVE-2023-52614', 'CVE-2023-52615', 'CVE-2023-52616', 'CVE-2023-52617', 'CVE-2023-52618', 'CVE-2023-52619', 'CVE-2023-52622', 'CVE-2023-52623', 'CVE-2023-52627', 'CVE-2023-52631', 'CVE-2023-52633', 'CVE-2023-52635', 'CVE-2023-52637', 'CVE-2023-52638', 'CVE-2023-52642', 'CVE-2023-52643', 'CVE-2024-1151', 'CVE-2024-2201', 'CVE-2024-23849', 'CVE-2024-26592', 'CVE-2024-26593', 'CVE-2024-26594', 'CVE-2024-26600', 'CVE-2024-26602', 'CVE-2024-26606', 'CVE-2024-26608', 'CVE-2024-26610', 'CVE-2024-26614', 'CVE-2024-26615', 'CVE-2024-26625', 'CVE-2024-26627', 'CVE-2024-26635', 'CVE-2024-26636', 'CVE-2024-26640', 'CVE-2024-26641', 'CVE-2024-26644', 'CVE-2024-26645', 'CVE-2024-26660', 'CVE-2024-26663', 'CVE-2024-26664', 'CVE-2024-26665', 'CVE-2024-26668', 'CVE-2024-26671', 'CVE-2024-26673', 'CVE-2024-26675', 'CVE-2024-26676', 'CVE-2024-26679', 'CVE-2024-26684', 'CVE-2024-26685', 'CVE-2024-26689', 'CVE-2024-26695', 'CVE-2024-26696', 'CVE-2024-26697', 'CVE-2024-26698', 'CVE-2024-26702', 'CVE-2024-26704', 'CVE-2024-26707', 'CVE-2024-26712', 'CVE-2024-26715', 'CVE-2024-26717', 'CVE-2024-26720', 'CVE-2024-26722', 'CVE-2024-26808', 'CVE-2024-26825', 'CVE-2024-26826', 'CVE-2024-26829', 'CVE-2024-26910', 'CVE-2024-26916', 'CVE-2024-26920');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6766-3');
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
