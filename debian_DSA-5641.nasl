#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5641. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192271);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id("CVE-2024-25081", "CVE-2024-25082");

  script_name(english:"Debian dsa-5641 : fontforge - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5641 advisory.

  - Splinefont in FontForge through 20230101 allows command injection via crafted filenames. (CVE-2024-25081)

  - Splinefont in FontForge through 20230101 allows command injection via crafted archives or compressed
    files. (CVE-2024-25082)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/fontforge");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-25081");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-25082");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/fontforge");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/fontforge");
  script_set_attribute(attribute:"solution", value:
"Upgrade the fontforge packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-25082");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fontforge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fontforge-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fontforge-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fontforge-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fontforge-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfontforge4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-fontforge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'fontforge', 'reference': '1:20201107~dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'fontforge-common', 'reference': '1:20201107~dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'fontforge-doc', 'reference': '1:20201107~dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'fontforge-extras', 'reference': '1:20201107~dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'fontforge-nox', 'reference': '1:20201107~dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'libfontforge4', 'reference': '1:20201107~dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'python3-fontforge', 'reference': '1:20201107~dfsg-4+deb11u1'},
    {'release': '12.0', 'prefix': 'fontforge', 'reference': '1:20230101~dfsg-1.1~deb12u1'},
    {'release': '12.0', 'prefix': 'fontforge-common', 'reference': '1:20230101~dfsg-1.1~deb12u1'},
    {'release': '12.0', 'prefix': 'fontforge-doc', 'reference': '1:20230101~dfsg-1.1~deb12u1'},
    {'release': '12.0', 'prefix': 'fontforge-extras', 'reference': '1:20230101~dfsg-1.1~deb12u1'},
    {'release': '12.0', 'prefix': 'fontforge-nox', 'reference': '1:20230101~dfsg-1.1~deb12u1'},
    {'release': '12.0', 'prefix': 'libfontforge4', 'reference': '1:20230101~dfsg-1.1~deb12u1'},
    {'release': '12.0', 'prefix': 'python3-fontforge', 'reference': '1:20230101~dfsg-1.1~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fontforge / fontforge-common / fontforge-doc / fontforge-extras / etc');
}
