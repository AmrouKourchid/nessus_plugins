#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6835-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200676);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id(
    "CVE-2023-52722",
    "CVE-2024-29510",
    "CVE-2024-33869",
    "CVE-2024-33870",
    "CVE-2024-33871"
  );
  script_xref(name:"IAVB", value:"2023-B-0097-S");
  script_xref(name:"USN", value:"6835-1");
  script_xref(name:"IAVB", value:"2024-B-0074-S");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.10 / 24.04 LTS : Ghostscript vulnerabilities (USN-6835-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.10 / 24.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6835-1 advisory.

    It was discovered that Ghostscript did not properly restrict eexec seeds to those specified by the Type 1
    Font Format standard when SAFER mode is used. An attacker could use this issue to bypass SAFER
    restrictions and cause unspecified impact. (CVE-2023-52722) This issue only affected Ubuntu 20.04 LTS,
    Ubuntu 22.04 LTS, and Ubuntu 23.10.

    Thomas Rinsma discovered that Ghostscript did not prevent changes to uniprint device argument strings
    after SAFER is activated, resulting in a format-string vulnerability. An attacker could possibly use this
    to execute arbitrary code. (CVE-2024-29510)

    Zdenek Hutyra discovered that Ghostscript did not properly perform path reduction when validating paths.
    An attacker could use this to access file locations outside of those allowed by SAFER policy and possibly
    execute arbitrary code. (CVE-2024-33869)

    Zdenek Hutyra discovered that Ghostscript did not properly check arguments when reducing paths. An
    attacker could use this to access file locations outside of those allowed by SAFER policy.
    (CVE-2024-33870)

    Zdenek Hutyra discovered that the Driver parameter for Ghostscript's opvp/oprp device allowed
    specifying the name of an arbitrary dynamic library to load. An attacker could use this to execute
    arbitrary code. (CVE-2024-33871)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6835-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52722");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-33871");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ghostscript Command Execution via Format String');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs10-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs9-common");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.10 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'ghostscript', 'pkgver': '9.50~dfsg-5ubuntu4.12'},
    {'osver': '20.04', 'pkgname': 'ghostscript-x', 'pkgver': '9.50~dfsg-5ubuntu4.12'},
    {'osver': '20.04', 'pkgname': 'libgs-dev', 'pkgver': '9.50~dfsg-5ubuntu4.12'},
    {'osver': '20.04', 'pkgname': 'libgs9', 'pkgver': '9.50~dfsg-5ubuntu4.12'},
    {'osver': '20.04', 'pkgname': 'libgs9-common', 'pkgver': '9.50~dfsg-5ubuntu4.12'},
    {'osver': '22.04', 'pkgname': 'ghostscript', 'pkgver': '9.55.0~dfsg1-0ubuntu5.7'},
    {'osver': '22.04', 'pkgname': 'ghostscript-x', 'pkgver': '9.55.0~dfsg1-0ubuntu5.7'},
    {'osver': '22.04', 'pkgname': 'libgs-dev', 'pkgver': '9.55.0~dfsg1-0ubuntu5.7'},
    {'osver': '22.04', 'pkgname': 'libgs9', 'pkgver': '9.55.0~dfsg1-0ubuntu5.7'},
    {'osver': '22.04', 'pkgname': 'libgs9-common', 'pkgver': '9.55.0~dfsg1-0ubuntu5.7'},
    {'osver': '23.10', 'pkgname': 'ghostscript', 'pkgver': '10.01.2~dfsg1-0ubuntu2.3'},
    {'osver': '23.10', 'pkgname': 'ghostscript-x', 'pkgver': '10.01.2~dfsg1-0ubuntu2.3'},
    {'osver': '23.10', 'pkgname': 'libgs-common', 'pkgver': '10.01.2~dfsg1-0ubuntu2.3'},
    {'osver': '23.10', 'pkgname': 'libgs-dev', 'pkgver': '10.01.2~dfsg1-0ubuntu2.3'},
    {'osver': '23.10', 'pkgname': 'libgs10', 'pkgver': '10.01.2~dfsg1-0ubuntu2.3'},
    {'osver': '23.10', 'pkgname': 'libgs10-common', 'pkgver': '10.01.2~dfsg1-0ubuntu2.3'},
    {'osver': '23.10', 'pkgname': 'libgs9-common', 'pkgver': '10.01.2~dfsg1-0ubuntu2.3'},
    {'osver': '24.04', 'pkgname': 'ghostscript', 'pkgver': '10.02.1~dfsg1-0ubuntu7.1'},
    {'osver': '24.04', 'pkgname': 'libgs-common', 'pkgver': '10.02.1~dfsg1-0ubuntu7.1'},
    {'osver': '24.04', 'pkgname': 'libgs-dev', 'pkgver': '10.02.1~dfsg1-0ubuntu7.1'},
    {'osver': '24.04', 'pkgname': 'libgs10', 'pkgver': '10.02.1~dfsg1-0ubuntu7.1'},
    {'osver': '24.04', 'pkgname': 'libgs10-common', 'pkgver': '10.02.1~dfsg1-0ubuntu7.1'}
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
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ghostscript / ghostscript-x / libgs-common / libgs-dev / libgs10 / etc');
}
