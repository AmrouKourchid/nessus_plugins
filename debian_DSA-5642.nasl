#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5642. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192309);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id("CVE-2023-50251", "CVE-2023-50252", "CVE-2024-25117");

  script_name(english:"Debian dsa-5642 : php-dompdf-svg-lib - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dsa-5642 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5642-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    March 20, 2024                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : php-dompdf-svg-lib
    CVE ID         : CVE-2023-50251 CVE-2023-50252 CVE-2024-25117

    Three security issues were discovered in php-svg-lib, a PHP library to
    read, parse and export to PDF SVG files, which could result in denial
    of service, restriction bypass or the execution of arbitrary code.

    For the stable distribution (bookworm), these problems have been fixed in
    version 0.5.0-3+deb12u1.

    We recommend that you upgrade your php-dompdf-svg-lib packages.

    For the detailed security status of php-dompdf-svg-lib please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/php-dompdf-svg-lib

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCgAdFiEEtuYvPRKsOElcDakFEMKTtsN8TjYFAmX7NGEACgkQEMKTtsN8
    TjYo5w/+Pg6R1qOP4p3GoBWg9kiHwZBLx/tkHW2FCGaKd4sDPboHvT73kzX3LEPn
    5R+hBOGW07jB9VKn5icPte+UH/pTyl+5CKHG/4r8U8wNru83/mHqOmjsyneVBSMy
    1wX8RLVYQ0vtm2AEF6a97bYydQC206YMnmoiaw90CWNib8k88Uvj3+OL+j8TcL7X
    1F88/QU/dzHejJ3Qrto9ImOBYryemKIIt/BgRNJ9Dl1yaEgSs8CiYEMDmJ0Wg10m
    pbH9MUIqmbGlrnJsfILMe0x9x9aut1QXxzFpyY9cEWgnM3khyZsdg2NAuak+VXoL
    2OIFZKtgqZh8/1SvTMTzr3ayDB3zAACtZGa+ZCXA0FXeEekY9IOmEoIICRX70QOi
    l9/F4RCPv45yaWSRBuG5nJcGogEfdpVEYURWDqs483PzVaQSE/rXCg4+xfaKG3f2
    91h2rp9+tIj4Vrlbu6YDu7hYQARaa1b/SD3aM6iqfxO6c5c0gHgKJmZOjRg6N1Cl
    xsSI+RhDJrw9N9YTZyzyunAV04gpdZVpOdqKH/YWI1NqB/VlpCvsOF0Hd7hh2T7R
    i0yUR65f1zZIs3UfdJ3MiNMgnJdi05ZnOIvNWxN9ZzgAOSlyjIl6qRtRDikcUewu
    bpBPzDuaLYPepVr60QIPHap7XNCohdRP0no5ows2pXgMzl3YCQU=
    =OY4q
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/php-dompdf-svg-lib
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d322688");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50251");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50252");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-25117");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/php-dompdf-svg-lib");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php-dompdf-svg-lib packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-25117");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-dompdf-svg-lib");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'php-dompdf-svg-lib', 'reference': '0.5.0-3+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php-dompdf-svg-lib');
}
