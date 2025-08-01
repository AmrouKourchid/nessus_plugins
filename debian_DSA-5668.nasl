#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5668. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(193664);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2024-3832",
    "CVE-2024-3833",
    "CVE-2024-3834",
    "CVE-2024-3837",
    "CVE-2024-3838",
    "CVE-2024-3839",
    "CVE-2024-3840",
    "CVE-2024-3841",
    "CVE-2024-3843",
    "CVE-2024-3844",
    "CVE-2024-3845",
    "CVE-2024-3846",
    "CVE-2024-3847"
  );

  script_name(english:"Debian dsa-5668 : chromium - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5668 advisory.

  - Object corruption in V8 in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to potentially
    exploit object corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-3832)

  - Object corruption in WebAssembly in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to
    potentially exploit object corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-3833)

  - Use after free in Downloads in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-3834)

  - Use after free in QUIC in Google Chrome prior to 124.0.6367.60 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2024-3837)

  - Inappropriate implementation in Autofill in Google Chrome prior to 124.0.6367.60 allowed an attacker who
    convinced a user to install a malicious app to perform UI spoofing via a crafted app. (Chromium security
    severity: Medium) (CVE-2024-3838)

  - Out of bounds read in Fonts in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2024-3839)

  - Insufficient policy enforcement in Site Isolation in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-3840)

  - Insufficient data validation in Browser Switcher in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to inject scripts or HTML into a privileged page via a malicious file. (Chromium security
    severity: Medium) (CVE-2024-3841)

  - Insufficient data validation in Downloads in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-3843)

  - Inappropriate implementation in Extensions in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to perform UI spoofing via a crafted Chrome Extension. (Chromium security severity: Low)
    (CVE-2024-3844)

  - Inappropriate implementation in Networks in Google Chrome prior to 124.0.6367.60 allowed a remote attacker
    to bypass mixed content policy via a crafted HTML page. (Chromium security severity: Low) (CVE-2024-3845)

  - Inappropriate implementation in Prompts in Google Chrome prior to 124.0.6367.60 allowed a remote attacker
    who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted HTML page.
    (Chromium security severity: Low) (CVE-2024-3846)

  - Insufficient policy enforcement in WebUI in Google Chrome prior to 124.0.6367.60 allowed a remote attacker
    to bypass content security policy via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2024-3847)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/chromium");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3832");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3833");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3834");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3837");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3838");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3839");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3840");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3841");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3843");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3844");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3845");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3846");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3847");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/chromium");
  script_set_attribute(attribute:"solution", value:
"Upgrade the chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3837");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-shell");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'chromium', 'reference': '124.0.6367.60-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-common', 'reference': '124.0.6367.60-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-driver', 'reference': '124.0.6367.60-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-l10n', 'reference': '124.0.6367.60-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-sandbox', 'reference': '124.0.6367.60-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-shell', 'reference': '124.0.6367.60-1~deb12u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium / chromium-common / chromium-driver / chromium-l10n / etc');
}
