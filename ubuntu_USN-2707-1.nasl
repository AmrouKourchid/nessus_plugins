#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2707-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85297);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2015-4495");
  script_xref(name:"USN", value:"2707-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Ubuntu 14.04 LTS : Firefox vulnerability (USN-2707-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-2707-1 advisory.

    Cody Crews discovered a way to violate the same-origin policy to inject script in to a non-privileged part
    of the PDF viewer. If a user were tricked in to opening a specially crafted website, an attacker could
    exploit this to read sensitive information from local files. (CVE-2015-4495)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2707-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4495");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-globalmenu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zh-hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zh-hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-mozsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2015-2020 Canonical, Inc. / NASL script (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'firefox', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-dev', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-globalmenu', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-af', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-an', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-as', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-az', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-be', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-br', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-da', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-de', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-el', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-en', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-es', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-et', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-he', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-id', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-is', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-it', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-km', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-or', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-si', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-te', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-th', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-testsuite', 'pkgver': '39.0.3+build2-0ubuntu0.14.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox / firefox-dev / firefox-globalmenu / firefox-locale-af / etc');
}
