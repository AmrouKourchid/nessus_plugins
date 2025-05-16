#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5619. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(190381);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-24575", "CVE-2024-24577");

  script_name(english:"Debian dsa-5619 : libgit2-1.1 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5619 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5619-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    February 09, 2024                     https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : libgit2
    CVE ID         : CVE-2024-24577 CVE-2024-24575

    Two vulnerabilities were discovered in libgit2, a low-level Git library,
    which may result in denial of service or potentially the execution of
    arbitrary code.

    For the oldstable distribution (bullseye), this problem has been fixed
    in version 1.1.0+dfsg.1-4+deb11u2.

    For the stable distribution (bookworm), this problem has been fixed in
    version 1.5.1+ds-1+deb12u1.

    We recommend that you upgrade your libgit2 packages.

    For the detailed security status of libgit2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libgit2

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCgAdFiEEtuYvPRKsOElcDakFEMKTtsN8TjYFAmXGeNgACgkQEMKTtsN8
    TjatpBAAtY1nwqlQFnE//mah+rLfyeOtoM0XutnWZasAALawlg6h9RKMaOy7R1D3
    MKk5o4i5U7KqQih6YtCTy4JDfgZzJ+kCVXD5uEWEW6qRZGnEMXYtgrAUkG7VNCcG
    MwGei4nQFf1ZyCsP1ShaWyXa/sVkLtVYvqrWdXRSxf9p5Ky3lQh3cd9GXK3sWUbn
    zF3UK0ZFkocEmIX4qLE60s1bMQb/IrlgXguSutMqC5EHiVRhBvINmf3zC+ggLvk5
    fNre4rKns7RizMrkBKYFVwCeCXaBtKYhyE7T3otWu5mGsanE1c7aGTZDIH9HpRsT
    1JR9W5XI5HcDusajDJNy5v+Wl2/ohIfB3kECsfPITVql832X5DtqSNazNLA0RnYu
    AOa+7wElLrh6X2yFrahViOmie4smfc97LznpPhAXqy++jxnnYDTLUK/BCX3bIp5R
    kCTz5s6fsi64/2SO9KQscw+zKzKHSrIuPU42JYxfpo17kVDWfhU0mUbyygKFQmSK
    UQndaGUYpLXk7Iv4aoAXXRlWjV21uxxByKziDfHalTfthp2BjTmVdEutD/cc6Uwk
    9OJFnCMPBat07l4HlOypv0iYddNj7HVqOvgQz7NUuYLuDvC8VwdLgy4XyI8HnKmF
    OpMv04eqbwbTnv8uKvvvFMOMLWUEkS081a5tHmdVx0mJWInRW5k=
    =ixWD
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libgit2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-24575");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-24577");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/libgit2");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libgit2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libgit2-1.1 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24577");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgit2-1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgit2-1.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgit2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgit2-fixtures");
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
    {'release': '11.0', 'prefix': 'libgit2-1.1', 'reference': '1.1.0+dfsg.1-4+deb11u2'},
    {'release': '11.0', 'prefix': 'libgit2-dev', 'reference': '1.1.0+dfsg.1-4+deb11u2'},
    {'release': '11.0', 'prefix': 'libgit2-fixtures', 'reference': '1.1.0+dfsg.1-4+deb11u2'},
    {'release': '12.0', 'prefix': 'libgit2-1.5', 'reference': '1.5.1+ds-1+deb12u1'},
    {'release': '12.0', 'prefix': 'libgit2-dev', 'reference': '1.5.1+ds-1+deb12u1'},
    {'release': '12.0', 'prefix': 'libgit2-fixtures', 'reference': '1.5.1+ds-1+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libgit2-1.1 / libgit2-1.5 / libgit2-dev / libgit2-fixtures');
}
