#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2296-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76706);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2014-1544",
    "CVE-2014-1547",
    "CVE-2014-1549",
    "CVE-2014-1550",
    "CVE-2014-1552",
    "CVE-2014-1555",
    "CVE-2014-1556",
    "CVE-2014-1557",
    "CVE-2014-1558",
    "CVE-2014-1559",
    "CVE-2014-1560"
  );
  script_bugtraq_id(
    68810,
    68811,
    68812,
    68813,
    68814,
    68815,
    68816,
    68820,
    68821,
    68822,
    68824
  );
  script_xref(name:"USN", value:"2296-1");

  script_name(english:"Ubuntu 14.04 LTS : Thunderbird vulnerabilities (USN-2296-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2296-1 advisory.

    Christian Holler, David Keeler and Byron Campen discovered multiple memory safety issues in Thunderbird.
    If a user were tricked in to opening a specially crafted message with scripting enabled, an attacker could
    potentially exploit these to cause a denial of service via application crash, or execute arbitrary code
    with the privileges of the user invoking Thunderbird. (CVE-2014-1547)

    Atte Kettunen discovered a buffer overflow when interacting with WebAudio buffers. If a user had enabled
    scripting, an attacker could potentially exploit this to cause a denial of service via application crash
    or execute arbitrary code with the privileges of the user invoking Thunderbird. (CVE-2014-1549)

    Atte Kettunen discovered a use-after-free in WebAudio. If a user had enabled scripting, an attacker could
    potentially exploit this to cause a denial of service via application crash or execute arbitrary code with
    the privileges of the user invoking Thunderbird. (CVE-2014-1550)

    Jethro Beekman discovered a use-after-free when the FireOnStateChange event is triggered in some
    circumstances. If a user had enabled scripting, an attacker could potentially exploit this to cause a
    denial of service via application crash or execute arbitrary code with the priviliges of the user invoking
    Thunderbird. (CVE-2014-1555)

    Patrick Cozzi discovered a crash when using the Cesium JS library to generate WebGL content. If a user had
    enabled scripting, an attacker could potentially exploit this to execute arbitrary code with the privilges
    of the user invoking Thunderbird. (CVE-2014-1556)

    Tyson Smith and Jesse Schwartzentruber discovered a use-after-free in CERT_DestroyCertificate. If a user
    had enabled scripting, an attacker could potentially exploit this to cause a denial of service via
    application crash or execute arbitrary code with the privileges of the user invoking Thunderbird.
    (CVE-2014-1544)

    A crash was discovered in Skia when scaling an image, if the scaling operation takes too long. If a user
    had enabled scripting, an attacker could potentially exploit this to execute arbitrary code with the
    privileges of the user invoking Thunderbird. (CVE-2014-1557)

    Christian Holler discovered several issues when parsing certificates with non-standard character encoding,
    resulting in the inability to use valid SSL certificates in some circumstances. (CVE-2014-1558,
    CVE-2014-1559, CVE-2014-1560)

    Boris Zbarsky discovered that network redirects could cause an iframe to escape the confinements defined
    by its sandbox attribute in some circumstances. If a user had enabled scripting, an attacker could
    potentially exploit this to conduct cross-site scripting attacks. (CVE-2014-1552)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2296-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1550");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-1557");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-globalmenu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ta-lk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-mozsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-calendar-timezones");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-gdata-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-lightning");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2014-2020 Canonical, Inc. / NASL script (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'thunderbird', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-dev', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-globalmenu', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'thunderbird-testsuite', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'},
    {'osver': '14.04', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:31.0+build1-0ubuntu0.14.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird / thunderbird-dev / thunderbird-globalmenu / etc');
}
