#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5618. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(190343);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-23206", "CVE-2024-23213", "CVE-2024-23222");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/13");

  script_name(english:"Debian dsa-5618 : gir1.2-javascriptcoregtk-4.0 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5618 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA256

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5618-1                   security@debian.org
    https://www.debian.org/security/                           Alberto Garcia
    February 08, 2024                     https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : webkit2gtk
    CVE ID         : CVE-2024-23206 CVE-2024-23213 CVE-2024-23222

    The following vulnerabilities have been discovered in the WebKitGTK
    web engine:

    CVE-2024-23206

        An anonymous researcher discovered that a maliciously crafted
        webpage may be able to fingerprint the user.

    CVE-2024-23213

        Wangtaiyu discovered that processing web content may lead to
        arbitrary code execution.

    CVE-2024-23222

        Apple discovered that processing maliciously crafted web content
        may lead to arbitrary code execution. Apple is aware of a report
        that this issue may have been exploited.

    For the oldstable distribution (bullseye), these problems have been fixed
    in version 2.42.5-1~deb11u1.

    For the stable distribution (bookworm), these problems have been fixed in
    version 2.42.5-1~deb12u1.

    We recommend that you upgrade your webkit2gtk packages.

    For the detailed security status of webkit2gtk please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/webkit2gtk

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCAAdFiEEYrwugQBKzlHMYFizAAyEYu0C2AIFAmXFXGQACgkQAAyEYu0C
    2AJWJA//fFEMVOvrgBf8I2Nnz37Bm/jR4IRM52osjsI6I23tjJ1vA9UR7Y/03QGN
    qOzfOsb6wcRGZfYdEy945N6vf/XN3opl44ApyJ6RHStbQ8EuTw+IXVSKs49x6FBC
    P7glTc3I4R5gYpOKDwc/jQwkB6VeCYPq0LeqgVNx2/Ja0eJ3KUEjXo+yYJbowRj+
    oiR9R+WKIEnz7BdxMbOLrlHc9CpR3UynozFprFha8bKNlyJAq/hwsO546NgYnSQH
    +n/hAad1NDvcptljLHrXjw/GYTVc2lEGoFFr8H8EDVdWrtzSlecHenthIxfjoKL9
    4eWGvilyZJGAKvtlaNRCFNorHTsAcqRUYhDT87TNScU+ONwdk3tdl9d4F/CcTylA
    7ZQGQ1OQk2f5h/E2Ns1CD0KE64+Qv4Eima/A7VNDKc2hXPNavaekIbziVKEJ4r+m
    ypJrJDm+RLeOcDKuyxfz6REQvAOinjMnfPQhMXRCdk4vz3RXl9bEpoao35C2rtLe
    HcL3/tg24hOooj6NJYQRuiKfmrZKhHivNrg4QJ/71Y1/JXtlmLiol6h8nfKKvb19
    ObFGbF27htKmSGXR3Oig5tQWcjhnbH4CSqXoTOYwDPRgb9dutViclKu605A97Fm5
    l5U0fyIT8mwkN/thk8KOE1AtNC2n90Y9Yx/gBPFRypHN+CBQCbY=
    =Lfkz
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/webkit2gtk");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/webkit2gtk");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23206");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23213");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23222");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/webkit2gtk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gir1.2-javascriptcoregtk-4.0 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23222");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-javascriptcoregtk-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-javascriptcoregtk-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-javascriptcoregtk-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-webkit-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-webkit2-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-webkit2-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-6.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-6.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.0-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkitgtk-6.0-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkitgtk-6.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webkit2gtk-driver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'gir1.2-javascriptcoregtk-4.0', 'reference': '2.42.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'gir1.2-webkit2-4.0', 'reference': '2.42.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libjavascriptcoregtk-4.0-18', 'reference': '2.42.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libjavascriptcoregtk-4.0-bin', 'reference': '2.42.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libjavascriptcoregtk-4.0-dev', 'reference': '2.42.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwebkit2gtk-4.0-37', 'reference': '2.42.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwebkit2gtk-4.0-dev', 'reference': '2.42.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwebkit2gtk-4.0-doc', 'reference': '2.42.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'webkit2gtk-driver', 'reference': '2.42.5-1~deb11u1'},
    {'release': '12.0', 'prefix': 'gir1.2-javascriptcoregtk-4.0', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'gir1.2-javascriptcoregtk-4.1', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'gir1.2-javascriptcoregtk-6.0', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'gir1.2-webkit-6.0', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'gir1.2-webkit2-4.0', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'gir1.2-webkit2-4.1', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-4.0-18', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-4.0-bin', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-4.0-dev', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-4.1-0', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-4.1-dev', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-6.0-1', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-6.0-dev', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkit2gtk-4.0-37', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkit2gtk-4.0-dev', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkit2gtk-4.0-doc', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkit2gtk-4.1-0', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkit2gtk-4.1-dev', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkitgtk-6.0-4', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkitgtk-6.0-dev', 'reference': '2.42.5-1~deb12u1'},
    {'release': '12.0', 'prefix': 'webkit2gtk-driver', 'reference': '2.42.5-1~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-javascriptcoregtk-4.0 / gir1.2-javascriptcoregtk-4.1 / etc');
}
