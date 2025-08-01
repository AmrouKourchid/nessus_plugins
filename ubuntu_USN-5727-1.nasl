#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5727-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167770);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2022-2153",
    "CVE-2022-2978",
    "CVE-2022-3028",
    "CVE-2022-3635",
    "CVE-2022-20422",
    "CVE-2022-36879",
    "CVE-2022-40768"
  );
  script_xref(name:"USN", value:"5727-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS : Linux kernel vulnerabilities (USN-5727-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-5727-1 advisory.

    It was discovered that a race condition existed in the instruction emulator of the Linux kernel on Arm
    64-bit systems. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2022-20422)

    It was discovered that the KVM implementation in the Linux kernel did not properly handle virtual CPUs
    without APICs in certain situations. A local attacker could possibly use this to cause a denial of service
    (host system crash). (CVE-2022-2153)

    Hao Sun and Jiacheng Xu discovered that the NILFS file system implementation in the Linux kernel contained
    a use-after-free vulnerability. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2022-2978)

    Abhishek Shah discovered a race condition in the PF_KEYv2 implementation in the Linux kernel. A local
    attacker could use this to cause a denial of service (system crash) or possibly expose sensitive
    information (kernel memory). (CVE-2022-3028)

    It was discovered that the IDT 77252 ATM PCI device driver in the Linux kernel did not properly remove any
    pending timers during device exit, resulting in a use-after-free vulnerability. A local attacker could
    possibly use this to cause a denial of service (system crash) or execute arbitrary code. (CVE-2022-3635)

    It was discovered that the Netlink Transformation (XFRM) subsystem in the Linux kernel contained a
    reference counting error. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2022-36879)

    Xingyuan Mo and Gengjia Chen discovered that the Promise SuperTrak EX storage controller driver in the
    Linux kernel did not properly handle certain structures. A local attacker could potentially use this to
    expose sensitive information (kernel memory). (CVE-2022-40768)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5727-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2978");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1055-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1108-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1121-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1129-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1139-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1143-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1143-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-197-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-197-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-197-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var kernel_mappings = {
  '16.04': {
    '4.15.0': {
      'generic': '4.15.0-197',
      'lowlatency': '4.15.0-197',
      'oracle': '4.15.0-1108',
      'aws': '4.15.0-1143',
      'aws-hwe': '4.15.0-1143'
    }
  },
  '18.04': {
    '4.15.0': {
      'generic': '4.15.0-197',
      'generic-lpae': '4.15.0-197',
      'lowlatency': '4.15.0-197',
      'dell300x': '4.15.0-1055',
      'oracle': '4.15.0-1108',
      'raspi2': '4.15.0-1121',
      'kvm': '4.15.0-1129',
      'snapdragon': '4.15.0-1139',
      'aws': '4.15.0-1143'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5727-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-2153', 'CVE-2022-2978', 'CVE-2022-3028', 'CVE-2022-3635', 'CVE-2022-20422', 'CVE-2022-36879', 'CVE-2022-40768');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5727-1');
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
