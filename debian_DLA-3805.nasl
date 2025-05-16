#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3805. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(194883);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2023-24607",
    "CVE-2023-32762",
    "CVE-2023-32763",
    "CVE-2023-33285",
    "CVE-2023-37369",
    "CVE-2023-38197",
    "CVE-2023-51714"
  );

  script_name(english:"Debian dla-3805 : libqt5concurrent5 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3805 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3805-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                    Thorsten Alteholz
    May 01, 2024                                  https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : qtbase-opensource-src
    Version        : 5.11.3+dfsg1-1+deb10u6
    CVE ID         : CVE-2023-24607 CVE-2023-32762 CVE-2023-32763
                     CVE-2023-33285 CVE-2023-37369 CVE-2023-38197
                     CVE-2023-51714


    Several issues have been found in qtbase-opensource-src, a collection of
    several Qt modules/libraries.
    The issues are related to buffer overflows, infinite loops or application
    crashs due to processing of crafted input files.



    For Debian 10 buster, these problems have been fixed in version
    5.11.3+dfsg1-1+deb10u6.

    We recommend that you upgrade your qtbase-opensource-src packages.

    For the detailed security status of qtbase-opensource-src please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/qtbase-opensource-src

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/qtbase-opensource-src
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?daec893f");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24607");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32762");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-33285");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37369");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38197");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-51714");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/qtbase-opensource-src");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libqt5concurrent5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-51714");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5concurrent5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5core5a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5dbus5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5opengl5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5opengl5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5printsupport5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5-ibase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt5-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt5-flatpak-platformtheme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt5-gtk-platformtheme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt5-qmake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt5-qmake-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-dev-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-private-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libqt5concurrent5', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5core5a', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5dbus5', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5gui5', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5network5', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5opengl5', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5opengl5-dev', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5printsupport5', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5sql5', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5sql5-ibase', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5sql5-mysql', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5sql5-odbc', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5sql5-psql', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5sql5-sqlite', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5sql5-tds', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5test5', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5widgets5', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libqt5xml5', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'qt5-default', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'qt5-flatpak-platformtheme', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'qt5-gtk-platformtheme', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'qt5-qmake', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'qt5-qmake-bin', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'qtbase5-dev', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'qtbase5-dev-tools', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'qtbase5-doc', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'qtbase5-doc-html', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'qtbase5-examples', 'reference': '5.11.3+dfsg1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'qtbase5-private-dev', 'reference': '5.11.3+dfsg1-1+deb10u6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libqt5concurrent5 / libqt5core5a / libqt5dbus5 / libqt5gui5 / etc');
}
