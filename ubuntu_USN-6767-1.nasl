#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6767-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195135);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2023-52435",
    "CVE-2023-52486",
    "CVE-2023-52583",
    "CVE-2023-52587",
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
    "CVE-2023-52615",
    "CVE-2023-52617",
    "CVE-2023-52619",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2023-52637",
    "CVE-2024-23849",
    "CVE-2024-26593",
    "CVE-2024-26598",
    "CVE-2024-26600",
    "CVE-2024-26602",
    "CVE-2024-26606",
    "CVE-2024-26615",
    "CVE-2024-26625",
    "CVE-2024-26635",
    "CVE-2024-26636",
    "CVE-2024-26645",
    "CVE-2024-26663",
    "CVE-2024-26664",
    "CVE-2024-26671",
    "CVE-2024-26673",
    "CVE-2024-26675",
    "CVE-2024-26679",
    "CVE-2024-26684",
    "CVE-2024-26685",
    "CVE-2024-26696",
    "CVE-2024-26697",
    "CVE-2024-26702",
    "CVE-2024-26704",
    "CVE-2024-26720",
    "CVE-2024-26722",
    "CVE-2024-26825",
    "CVE-2024-26910",
    "CVE-2024-26920"
  );
  script_xref(name:"USN", value:"6767-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-6767-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6767-1 advisory.

    Chenyuan Yang discovered that the RDS Protocol implementation in the Linux kernel contained an out-of-
    bounds read vulnerability. An attacker could use this to possibly cause a denial of service (system
    crash). (CVE-2024-23849)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - PowerPC architecture;

    - S390 architecture;

    - Block layer subsystem;

    - Android drivers;

    - Hardware random number generator core;

    - GPU drivers;

    - Hardware monitoring drivers;

    - I2C subsystem;

    - IIO Magnetometer sensors drivers;

    - InfiniBand drivers;

    - Network drivers;

    - PCI driver for MicroSemi Switchtec;

    - PHY drivers;

    - Ceph distributed file system;

    - Ext4 file system;

    - JFS file system;

    - NILFS2 file system;

    - Pstore file system;

    - Core kernel;

    - Memory management;

    - CAN network layer;

    - Networking core;

    - IPv4 networking;

    - Logical Link layer;

    - Netfilter;

    - NFC subsystem;

    - SMC sockets;

    - Sun RPC protocol;

    - TIPC protocol;

    - Realtek audio codecs; (CVE-2024-26696, CVE-2023-52583, CVE-2024-26720, CVE-2023-52615, CVE-2023-52599,
    CVE-2023-52587, CVE-2024-26635, CVE-2024-26704, CVE-2024-26625, CVE-2024-26825, CVE-2023-52622,
    CVE-2023-52435, CVE-2023-52617, CVE-2023-52598, CVE-2024-26645, CVE-2023-52619, CVE-2024-26593,
    CVE-2024-26685, CVE-2023-52602, CVE-2023-52486, CVE-2024-26697, CVE-2024-26675, CVE-2024-26600,
    CVE-2023-52604, CVE-2024-26664, CVE-2024-26606, CVE-2023-52594, CVE-2024-26671, CVE-2024-26598,
    CVE-2024-26673, CVE-2024-26920, CVE-2024-26722, CVE-2023-52601, CVE-2024-26602, CVE-2023-52637,
    CVE-2023-52623, CVE-2024-26702, CVE-2023-52597, CVE-2024-26684, CVE-2023-52606, CVE-2024-26679,
    CVE-2024-26663, CVE-2024-26910, CVE-2024-26615, CVE-2023-52595, CVE-2023-52607, CVE-2024-26636)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6767-1");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1036-iot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1043-xilinx-zynqmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1071-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1091-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1108-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1112-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1123-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1124-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1128-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1129-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-181-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-181-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-181-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024-2025 Canonical, Inc. / NASL script (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '5.4.0-181',
      'lowlatency': '5.4.0-181',
      'ibm': '5.4.0-1071',
      'raspi': '5.4.0-1108',
      'oracle': '5.4.0-1123',
      'aws': '5.4.0-1124',
      'gcp': '5.4.0-1128',
      'azure': '5.4.0-1129'
    }
  },
  '20.04': {
    '5.4.0': {
      'generic': '5.4.0-181',
      'generic-lpae': '5.4.0-181',
      'lowlatency': '5.4.0-181',
      'iot': '5.4.0-1036',
      'xilinx-zynqmp': '5.4.0-1043',
      'ibm': '5.4.0-1071',
      'gkeop': '5.4.0-1091',
      'raspi': '5.4.0-1108',
      'kvm': '5.4.0-1112',
      'oracle': '5.4.0-1123',
      'aws': '5.4.0-1124',
      'gcp': '5.4.0-1128',
      'azure': '5.4.0-1129'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6767-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-52435', 'CVE-2023-52486', 'CVE-2023-52583', 'CVE-2023-52587', 'CVE-2023-52594', 'CVE-2023-52595', 'CVE-2023-52597', 'CVE-2023-52598', 'CVE-2023-52599', 'CVE-2023-52601', 'CVE-2023-52602', 'CVE-2023-52604', 'CVE-2023-52606', 'CVE-2023-52607', 'CVE-2023-52615', 'CVE-2023-52617', 'CVE-2023-52619', 'CVE-2023-52622', 'CVE-2023-52623', 'CVE-2023-52637', 'CVE-2024-23849', 'CVE-2024-26593', 'CVE-2024-26598', 'CVE-2024-26600', 'CVE-2024-26602', 'CVE-2024-26606', 'CVE-2024-26615', 'CVE-2024-26625', 'CVE-2024-26635', 'CVE-2024-26636', 'CVE-2024-26645', 'CVE-2024-26663', 'CVE-2024-26664', 'CVE-2024-26671', 'CVE-2024-26673', 'CVE-2024-26675', 'CVE-2024-26679', 'CVE-2024-26684', 'CVE-2024-26685', 'CVE-2024-26696', 'CVE-2024-26697', 'CVE-2024-26702', 'CVE-2024-26704', 'CVE-2024-26720', 'CVE-2024-26722', 'CVE-2024-26825', 'CVE-2024-26910', 'CVE-2024-26920');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6767-1');
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
