#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5648. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192686);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2024-2625",
    "CVE-2024-2626",
    "CVE-2024-2627",
    "CVE-2024-2628",
    "CVE-2024-2629",
    "CVE-2024-2630",
    "CVE-2024-2631",
    "CVE-2024-2883",
    "CVE-2024-2885",
    "CVE-2024-2886",
    "CVE-2024-2887"
  );
  script_xref(name:"IAVA", value:"2024-A-0183-S");

  script_name(english:"Debian dsa-5648 : chromium - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5648 advisory.

  - Object lifecycle issue in V8 in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to
    potentially exploit object corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-2625)

  - Out of bounds read in Swiftshader in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-2626)

  - Use after free in Canvas in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2024-2627)

  - Inappropriate implementation in Downloads in Google Chrome prior to 123.0.6312.58 allowed a remote
    attacker to perform UI spoofing via a crafted URL. (Chromium security severity: Medium) (CVE-2024-2628)

  - Incorrect security UI in iOS in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to perform
    UI spoofing via a crafted HTML page. (Chromium security severity: Medium) (CVE-2024-2629)

  - Inappropriate implementation in iOS in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to
    leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium) (CVE-2024-2630)

  - Inappropriate implementation in iOS in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to
    perform UI spoofing via a crafted HTML page. (Chromium security severity: Low) (CVE-2024-2631)

  - Use after free in ANGLE in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical) (CVE-2024-2883)

  - Use after free in Dawn in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-2885)

  - Use after free in WebCodecs in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to perform
    arbitrary read/write via a crafted HTML page. (Chromium security severity: High) (CVE-2024-2886)

  - Type Confusion in WebAssembly in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to execute
    arbitrary code via a crafted HTML page. (Chromium security severity: High) (CVE-2024-2887)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/chromium");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2625");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2626");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2627");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2628");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2629");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2630");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2631");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2883");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2885");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2886");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2887");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/chromium");
  script_set_attribute(attribute:"solution", value:
"Upgrade the chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2885");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-shell");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '12.0', 'prefix': 'chromium', 'reference': '123.0.6312.86-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-common', 'reference': '123.0.6312.86-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-driver', 'reference': '123.0.6312.86-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-l10n', 'reference': '123.0.6312.86-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-sandbox', 'reference': '123.0.6312.86-1~deb12u1'},
    {'release': '12.0', 'prefix': 'chromium-shell', 'reference': '123.0.6312.86-1~deb12u1'}
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
