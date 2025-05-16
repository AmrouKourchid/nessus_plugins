#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2937-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(90094);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2014-1748",
    "CVE-2015-1071",
    "CVE-2015-1076",
    "CVE-2015-1081",
    "CVE-2015-1083",
    "CVE-2015-1120",
    "CVE-2015-1122",
    "CVE-2015-1127",
    "CVE-2015-1153",
    "CVE-2015-1155",
    "CVE-2015-3658",
    "CVE-2015-3659",
    "CVE-2015-3727",
    "CVE-2015-3731",
    "CVE-2015-3741",
    "CVE-2015-3743",
    "CVE-2015-3745",
    "CVE-2015-3747",
    "CVE-2015-3748",
    "CVE-2015-3749",
    "CVE-2015-3752",
    "CVE-2015-5788",
    "CVE-2015-5794",
    "CVE-2015-5801",
    "CVE-2015-5809",
    "CVE-2015-5822",
    "CVE-2015-5928"
  );
  script_xref(name:"USN", value:"2937-1");

  script_name(english:"Ubuntu 14.04 LTS : WebKitGTK+ vulnerabilities (USN-2937-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2937-1 advisory.

    A large number of security issues were discovered in the WebKitGTK+ Web and JavaScript engines. If a user
    were tricked into viewing a malicious website, a remote attacker could exploit a variety of issues related
    to web browser security, including cross-site scripting attacks, denial of service attacks, and arbitrary
    code execution.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2937-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5928");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-1153");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-3.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-3.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-3.0-25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkitgtk-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkitgtk-1.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkitgtk-3.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkitgtk-3.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkitgtk-3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkitgtk-common-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkitgtk-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-javascriptcoregtk-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-javascriptcoregtk-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-webkit-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-webkit-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-webkit2-3.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2016-2024 Canonical, Inc. / NASL script (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'gir1.2-javascriptcoregtk-1.0', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'gir1.2-javascriptcoregtk-3.0', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'gir1.2-webkit-1.0', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'gir1.2-webkit-3.0', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'gir1.2-webkit2-3.0', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libjavascriptcoregtk-1.0-0', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libjavascriptcoregtk-1.0-dev', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libjavascriptcoregtk-3.0-0', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libjavascriptcoregtk-3.0-bin', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libjavascriptcoregtk-3.0-dev', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libwebkit-dev', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libwebkit2gtk-3.0-25', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libwebkit2gtk-3.0-dev', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libwebkitgtk-1.0-0', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libwebkitgtk-1.0-common', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libwebkitgtk-3.0-0', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libwebkitgtk-3.0-common', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libwebkitgtk-3.0-dev', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libwebkitgtk-common-dev', 'pkgver': '2.4.10-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'libwebkitgtk-dev', 'pkgver': '2.4.10-0ubuntu0.14.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-javascriptcoregtk-1.0 / gir1.2-javascriptcoregtk-3.0 / etc');
}
