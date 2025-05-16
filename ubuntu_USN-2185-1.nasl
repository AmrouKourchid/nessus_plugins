#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2185-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73786);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2014-1492",
    "CVE-2014-1518",
    "CVE-2014-1519",
    "CVE-2014-1522",
    "CVE-2014-1523",
    "CVE-2014-1524",
    "CVE-2014-1525",
    "CVE-2014-1526",
    "CVE-2014-1528",
    "CVE-2014-1529",
    "CVE-2014-1530",
    "CVE-2014-1531",
    "CVE-2014-1532"
  );
  script_bugtraq_id(
    66356,
    67123,
    67125,
    67127,
    67129,
    67130,
    67131,
    67132,
    67133,
    67134,
    67135,
    67136,
    67137
  );
  script_xref(name:"USN", value:"2185-1");

  script_name(english:"Ubuntu 14.04 LTS : Firefox vulnerabilities (USN-2185-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2185-1 advisory.

    Bobby Holley, Carsten Book, Christoph Diehl, Gary Kwong, Jan de Mooij, Jesse Ruderman, Nathan Froyd, John
    Schoenick, Karl Tomlinson, Vladimir Vukicevic and Christian Holler discovered multiple memory safety
    issues in Firefox. If a user were tricked in to opening a specially crafted website, an attacker could
    potentially exploit these to cause a denial of service via application crash, or execute arbitrary code
    with the privileges of the user invoking Firefox. (CVE-2014-1518, CVE-2014-1519)

    An out of bounds read was discovered in Web Audio. An attacker could potentially exploit this cause a
    denial of service via application crash or execute arbitrary code with the privileges of the user invoking
    Firefox. (CVE-2014-1522)

    Abhishek Arya discovered an out of bounds read when decoding JPG images. An attacker could potentially
    exploit this to cause a denial of service via application crash. (CVE-2014-1523)

    Abhishek Arya discovered a buffer overflow when a script uses a non-XBL object as an XBL object. An
    attacker could potentially exploit this to execute arbitrary code with the privileges of the user invoking
    Firefox. (CVE-2014-1524)

    Abhishek Arya discovered a use-after-free in the Text Track Manager when processing HTML video. An
    attacker could potentially exploit this to cause a denial of service via application crash or execute
    arbitrary code with the privileges of the user invoking Firefox. (CVE-2014-1525)

    Jukka Jylnki discovered an out-of-bounds write in Cairo when working with canvas in some circumstances.
    An attacker could potentially exploit this to cause a denial of service via application crash or execute
    arbitrary code with the privileges of the user invoking Firefox. (CVE-2014-1528)

    Mariusz Mlynski discovered that sites with notification permissions can run script in a privileged context
    in some circumstances. An attacker could exploit this to execute arbitrary code with the privileges of the
    user invoking Firefox. (CVE-2014-1529)

    It was discovered that browser history navigations could be used to load a site with the addressbar
    displaying the wrong address. An attacker could potentially exploit this to conduct cross-site scripting
    or phishing attacks. (CVE-2014-1530)

    A use-after-free was discovered when resizing images in some circumstances. An attacker could potentially
    exploit this to cause a denial of service via application crash or execute arbitrary code with the
    privileges of the user invoking Firefox. (CVE-2014-1531)

    Christian Heimes discovered that NSS did not handle IDNA domain prefixes correctly for wildcard
    certificates. An attacker could potentially exploit this by using a specially crafted certificate to
    conduct a machine-in-the-middle attack. (CVE-2014-1492)

    Tyson Smith and Jesse Schwartzentruber discovered a use-after-free during host resolution in some
    circumstances. An attacker could potentially exploit this to cause a denial of service via application
    crash or execute arbitrary code with the privileges of the user invoking Firefox. (CVE-2014-1532)

    Boris Zbarsky discovered that the debugger bypassed XrayWrappers for some objects. If a user were tricked
    in to opening a specially crafted website whilst using the debugger, an attacker could potentially exploit
    this to execute arbitrary code with the privileges of the user invoking Firefox. (CVE-2014-1526)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2185-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1528");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-1532");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-globalmenu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ast");
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

  script_copyright(english:"Ubuntu Security Notice (C) 2014-2024 Canonical, Inc. / NASL script (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'firefox', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-dev', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-globalmenu', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-af', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-an', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-as', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-be', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-br', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-da', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-de', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-el', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-en', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-es', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-et', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-he', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-id', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-is', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-it', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-km', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-or', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-si', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-te', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-th', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'firefox-testsuite', 'pkgver': '29.0+build1-0ubuntu0.14.04.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox / firefox-dev / firefox-globalmenu / firefox-locale-af / etc');
}
