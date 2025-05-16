#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5617-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165248);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2020-0543",
    "CVE-2020-11739",
    "CVE-2020-11740",
    "CVE-2020-11741",
    "CVE-2020-11742",
    "CVE-2020-11743",
    "CVE-2020-15563",
    "CVE-2020-15564",
    "CVE-2020-15565",
    "CVE-2020-15566",
    "CVE-2020-15567",
    "CVE-2020-25595",
    "CVE-2020-25596",
    "CVE-2020-25597",
    "CVE-2020-25599",
    "CVE-2020-25600",
    "CVE-2020-25601",
    "CVE-2020-25602",
    "CVE-2020-25603",
    "CVE-2020-25604"
  );
  script_xref(name:"USN", value:"5617-1");

  script_name(english:"Ubuntu 20.04 LTS : Xen vulnerabilities (USN-5617-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5617-1 advisory.

    It was discovered that memory contents previously stored in microarchitectural special registers after
    RDRAND, RDSEED, and SGX EGETKEY read operations on Intel client and Xeon E3 processors may be briefly
    exposed to processes on the same or different processor cores. A local attacker could use this to expose
    sensitive information. (CVE-2020-0543)

    Julien Grall discovered that Xen incorrectly handled memory barriers on ARM-based systems. An attacker
    could possibly use this issue to cause a denial of service, obtain sensitive information or escalate
    privileges. (CVE-2020-11739)

    Ilja Van Sprundel discovered that Xen incorrectly handled profiling of guests. An unprivileged attacker
    could use this issue to obtain sensitive information from other guests, cause a denial of service or
    possibly gain privileges. (CVE-2020-11740, CVE-2020-11741)

    It was discovered that Xen incorrectly handled grant tables. A malicious guest could possibly use this
    issue to cause a denial of service. (CVE-2020-11742, CVE-2020-11743)

    Jan Beulich discovered that Xen incorrectly handled certain code paths. An attacker could possibly use
    this issue to cause a denial of service. (CVE-2020-15563)

    Julien Grall discovered that Xen incorrectly verified memory addresses provided by the guest on ARM-based
    systems. A malicious guest administrator could possibly use this issue to cause a denial of service.
    (CVE-2020-15564)

    Roger Pau Monn discovered that Xen incorrectly handled caching on x86 Intel systems. An attacker could
    possibly use this issue to cause a denial of service. (CVE-2020-15565)

    It was discovered that Xen incorrectly handled error in event-channel port allocation. A malicious guest
    could possibly use this issue to cause a denial of service. (CVE-2020-15566)

    Jan Beulich discovered that Xen incorrectly handled certain EPT (Extended Page Tables).

    An attacker could possibly use this issue to cause a denial of service, data corruption or privilege
    escalation. (CVE-2020-15567)

    Andrew Cooper discovered that Xen incorrectly handled PCI passthrough. An attacker could possibly use this
    issue to cause a denial of service. (CVE-2020-25595)

    Andrew Cooper discovered that Xen incorrectly sanitized path injections. An attacker could possibly use
    this issue to cause a denial of service. (CVE-2020-25596)

    Jan Beulich discovered that Xen incorrectly handled validation of event channels. An attacker could
    possibly use this issue to cause a denial of service. (CVE-2020-25597)

    Julien Grall and Jan Beulich discovered that Xen incorrectly handled resetting event channels. An attacker
    could possibly use this issue to cause a denial of service or obtain sensitive information.
    (CVE-2020-25599)

    Julien Grall discovered that Xen incorrectly handled event channels memory allocation on 32-bits domains.
    An attacker could possibly use this issue to cause a denial of service. (CVE-2020-25600)

    Jan Beulich discovered that Xen incorrectly handled resetting or cleaning up event channels. An attacker
    could possibly use this issue to cause a denial of service. (CVE-2020-25601)

    Andrew Cooper discovered that Xen incorrectly handled certain Intel specific MSR (Model Specific
    Registers). An attacker could possibly use this issue to cause a denial of service. (CVE-2020-25602)

    Julien Grall discovered that Xen incorrectly handled accessing/allocating event channels. An attacker
    could possibly use this issue to cause a denial of service, obtain sensitive information of privilege
    escalation. (CVE-2020-25603)

    Igor Druzhinin discovered that Xen incorrectly handled locks. An attacker could possibly use this issue to
    cause a denial of service. (CVE-2020-25604)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5617-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11741");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-15565");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxen-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxencall1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxendevicemodel1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxenevtchn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxenforeignmemory1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxengnttab1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxenmisc4.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxenstore3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxentoolcore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxentoollog1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-4.11-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-4.11-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-4.11-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-4.9-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-4.9-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-4.9-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-system-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-system-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-system-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-utils-4.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-utils-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xenstore-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libxen-dev', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxencall1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxendevicemodel1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxenevtchn1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxenforeignmemory1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxengnttab1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxenmisc4.11', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxenstore3.0', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxentoolcore1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxentoollog1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-4.11-amd64', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-4.11-arm64', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-4.11-armhf', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-4.9-amd64', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-4.9-arm64', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-4.9-armhf', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-common', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-system-amd64', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-system-arm64', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-system-armhf', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-utils-4.11', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-utils-common', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xenstore-utils', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  var extra = '';
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxen-dev / libxencall1 / libxendevicemodel1 / libxenevtchn1 / etc');
}
