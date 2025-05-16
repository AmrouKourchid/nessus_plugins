#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3315-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100835);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2017-5470",
    "CVE-2017-5471",
    "CVE-2017-5472",
    "CVE-2017-7749",
    "CVE-2017-7750",
    "CVE-2017-7751",
    "CVE-2017-7752",
    "CVE-2017-7754",
    "CVE-2017-7756",
    "CVE-2017-7757",
    "CVE-2017-7758",
    "CVE-2017-7762",
    "CVE-2017-7764",
    "CVE-2017-7771",
    "CVE-2017-7772",
    "CVE-2017-7773",
    "CVE-2017-7774",
    "CVE-2017-7776",
    "CVE-2017-7777",
    "CVE-2017-7778"
  );
  script_xref(name:"USN", value:"3315-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : Firefox vulnerabilities (USN-3315-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, read
uninitialized memory, obtain sensitive information, spoof the
addressbar contents, or execute arbitrary code. (CVE-2017-5470,
CVE-2017-5471, CVE-2017-5472, CVE-2017-7749, CVE-2017-7750,
CVE-2017-7751, CVE-2017-7752, CVE-2017-7754, CVE-2017-7756,
CVE-2017-7757, CVE-2017-7758, CVE-2017-7762, CVE-2017-7764)

Multiple security issues were discovered in the Graphite 2 library
used by Firefox. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause
a denial of service, read uninitialized memory, or execute arbitrary
code. (CVE-2017-7771, CVE-2017-7772, CVE-2017-7773, CVE-2017-7774,
CVE-2017-7776, CVE-2017-7777, CVE-2017-7778).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3315-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7778");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/16");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-cak");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gn");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-kab");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-my");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zh-hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zh-hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-mozsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2017-2024 Canonical, Inc. / NASL script (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'firefox', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-dev', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-globalmenu', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-af', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-an', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-as', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-az', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-be', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-br', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-da', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-de', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-el', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-en', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-es', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-et', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-he', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-id', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-is', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-it', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-km', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-my', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-or', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-si', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-te', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-th', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'firefox-testsuite', 'pkgver': '54.0+build3-0ubuntu0.14.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-dev', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-globalmenu', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-af', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-an', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-as', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-az', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-be', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-br', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-da', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-de', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-el', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-en', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-es', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-et', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-he', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-id', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-is', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-it', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-km', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-my', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-or', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-si', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-te', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-th', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-testsuite', 'pkgver': '54.0+build3-0ubuntu0.16.04.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
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
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox / firefox-dev / firefox-globalmenu / firefox-locale-af / etc');
}
