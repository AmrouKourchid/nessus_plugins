#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6314-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180258);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2020-36691",
    "CVE-2022-0168",
    "CVE-2022-1184",
    "CVE-2022-4269",
    "CVE-2022-27672",
    "CVE-2023-0590",
    "CVE-2023-1611",
    "CVE-2023-1855",
    "CVE-2023-1990",
    "CVE-2023-2124",
    "CVE-2023-2194",
    "CVE-2023-3111",
    "CVE-2023-3141",
    "CVE-2023-28466",
    "CVE-2023-30772",
    "CVE-2023-33203"
  );
  script_xref(name:"USN", value:"6314-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel vulnerabilities (USN-6314-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6314-1 advisory.

    It was discovered that the netlink implementation in the Linux kernel did not properly validate policies
    when parsing attributes in some situations. An attacker could use this to cause a denial of service
    (infinite recursion). (CVE-2020-36691)

    Billy Jheng Bing Jhong discovered that the CIFS network file system implementation in the Linux kernel did
    not properly validate arguments to ioctl() in some situations. A local attacker could possibly use this to
    cause a denial of service (system crash). (CVE-2022-0168)

    It was discovered that the ext4 file system implementation in the Linux kernel contained a use-after-free
    vulnerability. An attacker could use this to construct a malicious ext4 file system image that, when
    mounted, could cause a denial of service (system crash). (CVE-2022-1184)

    It was discovered that some AMD x86-64 processors with SMT enabled could speculatively execute
    instructions using a return address from a sibling thread. A local attacker could possibly use this to
    expose sensitive information. (CVE-2022-27672)

    William Zhao discovered that the Traffic Control (TC) subsystem in the Linux kernel did not properly
    handle network packet retransmission in certain situations. A local attacker could use this to cause a
    denial of service (kernel deadlock). (CVE-2022-4269)

    It was discovered that a race condition existed in the qdisc implementation in the Linux kernel, leading
    to a use-after-free vulnerability. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2023-0590)

    It was discovered that a race condition existed in the btrfs file system implementation in the Linux
    kernel, leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of
    service (system crash) or possibly expose sensitive information. (CVE-2023-1611)

    It was discovered that the APM X-Gene SoC hardware monitoring driver in the Linux kernel contained a race
    condition, leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of
    service (system crash) or expose sensitive information (kernel memory). (CVE-2023-1855)

    It was discovered that the ST NCI NFC driver did not properly handle device removal events. A physically
    proximate attacker could use this to cause a denial of service (system crash). (CVE-2023-1990)

    It was discovered that the XFS file system implementation in the Linux kernel did not properly perform
    metadata validation when mounting certain images. An attacker could use this to specially craft a file
    system image that, when mounted, could cause a denial of service (system crash). (CVE-2023-2124)

    It was discovered that the SLIMpro I2C device driver in the Linux kernel did not properly validate user-
    supplied data in some situations, leading to an out-of-bounds write vulnerability. A privileged attacker
    could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2023-2194)

    It was discovered that a race condition existed in the TLS subsystem in the Linux kernel, leading to a
    use-after-free or a null pointer dereference vulnerability. A local attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-28466)

    It was discovered that the DA9150 charger driver in the Linux kernel did not properly handle device
    removal, leading to a user-after free vulnerability. A physically proximate attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-30772)

    It was discovered that the btrfs file system implementation in the Linux kernel did not properly handle
    error conditions in some situations, leading to a use-after-free vulnerability. A local attacker could
    possibly use this to cause a denial of service (system crash). (CVE-2023-3111)

    It was discovered that the Ricoh R5C592 MemoryStick card reader driver in the Linux kernel contained a
    race condition during module unload, leading to a use-after-free vulnerability. A local attacker could use
    this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-3141)

    It was discovered that the Qualcomm EMAC ethernet driver in the Linux kernel did not properly handle
    device removal, leading to a user-after free vulnerability. A physically proximate attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-33203)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6314-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3111");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1054-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1068-bluefield");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '20.04': {
    '5.4.0': {
      'ibm': '5.4.0-1054',
      'bluefield': '5.4.0-1068'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6314-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2020-36691', 'CVE-2022-0168', 'CVE-2022-1184', 'CVE-2022-4269', 'CVE-2022-27672', 'CVE-2023-0590', 'CVE-2023-1611', 'CVE-2023-1855', 'CVE-2023-1990', 'CVE-2023-2124', 'CVE-2023-2194', 'CVE-2023-3111', 'CVE-2023-3141', 'CVE-2023-28466', 'CVE-2023-30772', 'CVE-2023-33203');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6314-1');
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
