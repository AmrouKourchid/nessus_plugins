#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2505-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81544);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2015-0819",
    "CVE-2015-0820",
    "CVE-2015-0821",
    "CVE-2015-0822",
    "CVE-2015-0823",
    "CVE-2015-0824",
    "CVE-2015-0825",
    "CVE-2015-0826",
    "CVE-2015-0827",
    "CVE-2015-0829",
    "CVE-2015-0830",
    "CVE-2015-0831",
    "CVE-2015-0832",
    "CVE-2015-0834",
    "CVE-2015-0835",
    "CVE-2015-0836"
  );
  script_bugtraq_id(
    72741,
    72742,
    72743,
    72745,
    72746,
    72748,
    72750,
    72751,
    72752,
    72753,
    72754,
    72755,
    72756,
    72757,
    72758,
    72759
  );
  script_xref(name:"USN", value:"2505-1");

  script_name(english:"Ubuntu 14.04 LTS : Firefox vulnerabilities (USN-2505-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2505-1 advisory.

    Matthew Noorenberghe discovered that Mozilla domains in the allowlist could make UITour API calls from
    background tabs. If one of these domains were compromised and open in a background tab, an attacker could

    potentially exploit this to conduct clickjacking attacks. (CVE-2015-0819)

    Jan de Mooij discovered an issue that affects content using the Caja Compiler. If web content loads
    specially crafted code, this could be used to bypass sandboxing security measures provided by Caja.
    (CVE-2015-0820)

    Armin Razmdjou discovered that opening hyperlinks with specific mouse and key combinations could allow a
    Chrome privileged URL to be opened without context restrictions being preserved. If a user were tricked in
    to opening a specially crafted website, an attacker could potentially exploit this to bypass security
    restrictions. (CVE-2015-0821)

    Armin Razmdjou discovered that contents of locally readable files could be made available via manipulation
    of form autocomplete in some circumstances. If a user were tricked in to opening a specially crafted
    website, an attacker could potentially exploit this to obtain sensitive information. (CVE-2015-0822)

    Atte Kettunen discovered a use-after-free in the OpenType Sanitiser (OTS) in some circumstances. If a user
    were tricked in to opening a specially crafted website, an attacker could potentially exploit this to
    cause a denial of service via application crash. (CVE-2015-0823)

    Atte Kettunen discovered a crash when drawing images using Cairo in some circumstances. If a user were
    tricked in to opening a specially crafted website, an attacker could potentially exploit this to cause a
    denial of service. (CVE-2015-0824)

    Atte Kettunen discovered a buffer underflow during playback of MP3 files in some circumstances. If a user
    were tricked in to opening a specially crafted website, an attacker could potentially exploit this to
    obtain sensitive information. (CVE-2015-0825)

    Atte Kettunen discovered a buffer overflow during CSS restyling in some circumstances. If a user were
    tricked in to opening a specially crafted website, an attacker could potentially exploit this to cause a
    denial of service via application crash, or execute arbitrary code with the privileges of the user
    invoking Firefox. (CVE-2015-0826)

    Abhishek Arya discovered an out-of-bounds read and write when rendering SVG content in some circumstances.
    If a user were tricked in to opening a specially crafted website, an attacker could potentially exploit
    this to obtain sensitive information. (CVE-2015-0827)

    A buffer overflow was discovered in libstagefright during video playback in some circumstances. If a user
    were tricked in to opening a specially crafted website, an attacker could potentially exploit this to
    cause a denial of service via application crash, or execute arbitrary code with the privileges of the user
    invoking Firefox. (CVE-2015-0829)

    Daniele Di Proietto discovered that WebGL could cause a crash in some circumstances. If a user were
    tricked in to opening a specially crafted website, an attacker could potentially exploit this to cause a
    denial of service. (CVE-2015-0830)

    Paul Bandha discovered a use-after-free in IndexedDB. If a user were tricked in to opening a specially
    crafted website, an attacker could potentially exploit this to cause a denial of service via application
    crash, or execute arbitrary code with the privileges of the user invoking Firefox. (CVE-2015-0831)

    Muneaki Nishimura discovered that a period appended to a hostname could bypass key pinning and HSTS in
    some circumstances. A remote attacker could potentially exloit this to conduct a Machine-in-the-middle
    (MITM) attack. (CVE-2015-0832)

    Alexander Kolesnik discovered that Firefox would attempt plaintext connections to servers when handling
    turns: and stuns: URIs. A remote attacker could potentially exploit this by conducting a Machine-in-the-
    middle (MITM) attack in order to obtain credentials. (CVE-2015-0834)

    Carsten Book, Christoph Diehl, Gary Kwong, Jan de Mooij, Liz Henry, Byron Campen, Tom Schuster, Ryan
    VanderMeulen, Christian Holler, Jesse Ruderman, Randell Jesup, Robin Whittleton, Jon Coppeard, and Nikhil
    Marathe discovered multiple memory safety issues in Firefox. If a user were tricked in to opening a
    specially crafted website, an attacker could potentially exploit these to cause a denial of service via
    application crash, or execute arbitrary code with the privileges of the user invoking Firefox.
    (CVE-2015-0835, CVE-2015-0836)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2505-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0836");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-0826");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/26");

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
    {'osver': '14.04', 'pkgname': 'firefox', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-dev', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-globalmenu', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-af', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-an', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-as', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-az', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-be', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-br', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-da', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-de', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-el', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-en', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-es', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-et', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-he', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-id', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-is', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-it', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-km', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-or', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-si', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-te', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-th', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'firefox-testsuite', 'pkgver': '36.0+build2-0ubuntu0.14.04.4'}
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
