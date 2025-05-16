#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5264-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157371);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id("CVE-2018-10196", "CVE-2019-11023", "CVE-2020-18032");
  script_xref(name:"USN", value:"5264-1");

  script_name(english:"Ubuntu 16.04 ESM : Graphviz vulnerabilities (USN-5264-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5264-1 advisory.

    It was discovered that graphviz contains null pointer dereference

    vulnerabilities. Exploitation via a specially crafted input file

    can cause a denial of service. (CVE-2018-10196, CVE-2019-11023)

    It was discovered that graphviz contains a buffer overflow

    vulnerability. Exploitation via a specially crafted input file can cause a denial of service or possibly
    allow for arbitrary code execution.

    (CVE-2020-18032)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5264-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-18032");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:graphviz-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcgraph6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphviz-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgv-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgv-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgv-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgv-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgv-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgv-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgvc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgvc6-plugins-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgvpr2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpathplan4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxdot4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'graphviz', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'graphviz-dev', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcdt5', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcgraph6', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgraphviz-dev', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgv-guile', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgv-lua', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgv-perl', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgv-python', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgv-ruby', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgv-tcl', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgvc6', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgvc6-plugins-gtk', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgvpr2', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpathplan4', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libxdot4', 'pkgver': '2.38.0-12ubuntu2.1+esm1', 'ubuntu_pro': TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'graphviz / graphviz-dev / libcdt5 / libcgraph6 / libgraphviz-dev / etc');
}
