#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6252-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178913);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id(
    "CVE-2022-1184",
    "CVE-2022-3303",
    "CVE-2023-1611",
    "CVE-2023-1670",
    "CVE-2023-1859",
    "CVE-2023-1990",
    "CVE-2023-2124",
    "CVE-2023-3090",
    "CVE-2023-3111",
    "CVE-2023-3141",
    "CVE-2023-3268",
    "CVE-2023-3390",
    "CVE-2023-35001"
  );
  script_xref(name:"USN", value:"6252-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM : Linux kernel vulnerabilities (USN-6252-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6252-1 advisory.

    It was discovered that the ext4 file system implementation in the Linux kernel contained a use-after-free
    vulnerability. An attacker could use this to construct a malicious ext4 file system image that, when
    mounted, could cause a denial of service (system crash). (CVE-2022-1184)

    It was discovered that the sound subsystem in the Linux kernel contained a race condition in some
    situations. A local attacker could use this to cause a denial of service (system crash). (CVE-2022-3303)

    It was discovered that a race condition existed in the btrfs file system implementation in the Linux
    kernel, leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of
    service (system crash) or possibly expose sensitive information. (CVE-2023-1611)

    It was discovered that the Xircom PCMCIA network device driver in the Linux kernel did not properly handle
    device removal events. A physically proximate attacker could use this to cause a denial of service (system
    crash). (CVE-2023-1670)

    It was discovered that a race condition existed in the Xen transport layer implementation for the 9P file
    system protocol in the Linux kernel, leading to a use-after-free vulnerability. A local attacker could use
    this to cause a denial of service (guest crash) or expose sensitive information (guest kernel memory).
    (CVE-2023-1859)

    It was discovered that the ST NCI NFC driver did not properly handle device removal events. A physically
    proximate attacker could use this to cause a denial of service (system crash). (CVE-2023-1990)

    It was discovered that the XFS file system implementation in the Linux kernel did not properly perform
    metadata validation when mounting certain images. An attacker could use this to specially craft a file
    system image that, when mounted, could cause a denial of service (system crash). (CVE-2023-2124)

    It was discovered that the IP-VLAN network driver for the Linux kernel did not properly initialize memory
    in some situations, leading to an out-of- bounds write vulnerability. An attacker could use this to cause
    a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-3090)

    It was discovered that the btrfs file system implementation in the Linux kernel did not properly handle
    error conditions in some situations, leading to a use-after-free vulnerability. A local attacker could
    possibly use this to cause a denial of service (system crash). (CVE-2023-3111)

    It was discovered that the Ricoh R5C592 MemoryStick card reader driver in the Linux kernel contained a
    race condition during module unload, leading to a use-after-free vulnerability. A local attacker could use
    this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-3141)

    It was discovered that the kernel->user space relay implementation in the Linux kernel did not properly
    perform certain buffer calculations, leading to an out-of-bounds read vulnerability. A local attacker
    could use this to cause a denial of service (system crash) or expose sensitive information (kernel
    memory). (CVE-2023-3268)

    It was discovered that the netfilter subsystem in the Linux kernel did not properly handle some error
    conditions, leading to a use-after-free vulnerability. A local attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2023-3390)

    Tanguy Dubroca discovered that the netfilter subsystem in the Linux kernel did not properly handle certain
    pointer data type, leading to an out-of- bounds write vulnerability. A privileged attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-35001)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6252-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35001");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1068-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1122-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1143-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1153-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1159-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1168-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-214-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-214-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-214-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2025 Canonical, Inc. / NASL script (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '4.15.0-214',
      'lowlatency': '4.15.0-214',
      'oracle': '4.15.0-1122',
      'gcp': '4.15.0-1153',
      'aws': '4.15.0-1159',
      'azure': '4.15.0-1168'
    }
  },
  '18.04': {
    '4.15.0': {
      'generic': '4.15.0-214',
      'generic-lpae': '4.15.0-214',
      'lowlatency': '4.15.0-214',
      'dell300x': '4.15.0-1068',
      'kvm': '4.15.0-1143',
      'gcp': '4.15.0-1153',
      'aws': '4.15.0-1159',
      'azure': '4.15.0-1168'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6252-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-1184', 'CVE-2022-3303', 'CVE-2023-1611', 'CVE-2023-1670', 'CVE-2023-1859', 'CVE-2023-1990', 'CVE-2023-2124', 'CVE-2023-3090', 'CVE-2023-3111', 'CVE-2023-3141', 'CVE-2023-3268', 'CVE-2023-3390', 'CVE-2023-35001');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6252-1');
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
