#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3864. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(206423);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/23");

  script_cve_id(
    "CVE-2024-4558",
    "CVE-2024-40776",
    "CVE-2024-40779",
    "CVE-2024-40780",
    "CVE-2024-40782",
    "CVE-2024-40785",
    "CVE-2024-40789",
    "CVE-2024-40794"
  );

  script_name(english:"Debian dla-3864 : gir1.2-javascriptcoregtk-4.0 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3864 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3864-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/               Emilio Pozuelo Monfort
    September 02, 2024                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : webkit2gtk
    Version        : 2.44.3-1~deb11u1
    CVE ID         : CVE-2024-4558 CVE-2024-40776 CVE-2024-40779 CVE-2024-40780
                     CVE-2024-40782 CVE-2024-40785 CVE-2024-40789 CVE-2024-40794

    The following vulnerabilities have been discovered in the WebKitGTK
    web engine:

    CVE-2024-4558

        An anonymous researcher discovered that processing maliciously
        crafted web content may lead to an unexpected process crash.

    CVE-2024-40776

        Huang Xilin discovered that processing maliciously crafted web
        content may lead to an unexpected process crash.

    CVE-2024-40779

        Huang Xilin discovered that processing maliciously crafted web
        content may lead to an unexpected process crash.

    CVE-2024-40780

        Huang Xilin dicovered that processing maliciously crafted web
        content may lead to an unexpected process crash.

    CVE-2024-40782

        Maksymilian Motyl discovered that processing maliciously crafted
        web content may lead to an unexpected process crash.

    CVE-2024-40785

        Johan Carlsson discovered that processing maliciously crafted web
        content may lead to a cross site scripting attack.

    CVE-2024-40789

        Seunghyun Lee discovered that processing maliciously crafted web
        content may lead to an unexpected process crash.

    CVE-2024-40794

        Matthew Butler discovered that private Browsing tabs may be
        accessed without authentication.

    For Debian 11 bullseye, these problems have been fixed in version
    2.44.3-1~deb11u1.

    We recommend that you upgrade your webkit2gtk packages.

    For the detailed security status of webkit2gtk please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/webkit2gtk

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/webkit2gtk");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40776");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40779");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40780");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40782");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40785");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40789");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40794");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-4558");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/webkit2gtk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gir1.2-javascriptcoregtk-4.0 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4558");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-javascriptcoregtk-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-webkit2-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.0-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webkit2gtk-driver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'gir1.2-javascriptcoregtk-4.0', 'reference': '2.44.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'gir1.2-webkit2-4.0', 'reference': '2.44.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libjavascriptcoregtk-4.0-18', 'reference': '2.44.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libjavascriptcoregtk-4.0-bin', 'reference': '2.44.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libjavascriptcoregtk-4.0-dev', 'reference': '2.44.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwebkit2gtk-4.0-37', 'reference': '2.44.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwebkit2gtk-4.0-dev', 'reference': '2.44.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwebkit2gtk-4.0-doc', 'reference': '2.44.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'webkit2gtk-driver', 'reference': '2.44.3-1~deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-javascriptcoregtk-4.0 / gir1.2-webkit2-4.0 / etc');
}
