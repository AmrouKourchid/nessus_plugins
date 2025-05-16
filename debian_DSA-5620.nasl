#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5620. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(190510);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2023-50387", "CVE-2023-50868");

  script_name(english:"Debian dsa-5620 : libunbound-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5620 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5620-1                   security@debian.org
    https://www.debian.org/security/                     Salvatore Bonaccorso
    February 14, 2024                     https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : unbound
    CVE ID         : CVE-2023-50387 CVE-2023-50868
    Debian Bug     : 1063845

    Two vulnerabilities were discovered in unbound, a validating, recursive,
    caching DNS resolver. Specially crafted DNSSEC answers could lead
    unbound down a very CPU intensive and time costly DNSSEC
    (CVE-2023-50387) or NSEC3 hash (CVE-2023-50868) validation path,
    resulting in denial of service.

    Details can be found at
    https://nlnetlabs.nl/downloads/unbound/CVE-2023-50387_CVE-2023-50868.txt

    For the oldstable distribution (bullseye), these problems have been fixed
    in version 1.13.1-1+deb11u2.

    For the stable distribution (bookworm), these problems have been fixed in
    version 1.17.1-2+deb12u2.

    We recommend that you upgrade your unbound packages.

    For the detailed security status of unbound please refer to its security
    tracker page at:
    https://security-tracker.debian.org/tracker/unbound

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQKTBAEBCgB9FiEERkRAmAjBceBVMd3uBUy48xNDz0QFAmXMYixfFIAAAAAALgAo
    aXNzdWVyLWZwckBub3RhdGlvbnMub3BlbnBncC5maWZ0aGhvcnNlbWFuLm5ldDQ2
    NDQ0MDk4MDhDMTcxRTA1NTMxRERFRTA1NENCOEYzMTM0M0NGNDQACgkQBUy48xND
    z0TxMxAAmy00/kTKXoaX+YGFHPIZmwdtP/eQnx9SreT40TrvASi7O5d/LKQUhMpY
    fEPqekyPCmfa/XkFZZVecyaNInoeyuf2olpQ5+gTgZMoxllccCFWqyO+TVhJtobf
    8iJttIwwdGYToH/tENr2Ady2Rgg5oy8WILF/5F2bckn2dgQAWUw4Tl7K9rkCf1Jr
    yO4KJGhXtNpaQZJnvX5dmwm7gDwkXsc9j85diRTRUF14IaMiiPKUpcxmogOGDYJc
    vY6lBFdLOfmzo1f3BO8SzNV+G0h7kCn/7w9RdpOWqTQoZHdT6IkT0YsZzLuJ0bVy
    oLWxi8Kh4fdAbEiyffVk0kLOWUmup9hckUSIXQktvOK6koFecm01W8OBzQ/HsB/D
    NExfo1l7GjAaAv+EkQHMdkiMqdoLI4oduuBxa2nFdCpDESaTN7Li6S0JtVc1YUu+
    UKHido3J0/U4xleL8sPPupJ2yVwOmbkeqK3hxH0J+e/uDT6mfrZ0moEEjOyAper8
    lqu4TS7rSK0e6/nNQs8dEEcoQQL1B3HXyXqjOBcMM4A1wPkJib8j2use64/+vIz6
    9tMflOwUxBirQ/J4PGLWTQmIoxF6NNzqTWgeFMIuq1NXIy7t3TPIIgW3+VWsNJwK
    Ae8HGZITdiBpGdSDFEa5qYKtiYQS6NxSx/fzyYNlfv7rUzrSNgQ=
    =m2j/
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/unbound");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/unbound");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50387");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50868");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/unbound");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libunbound-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50387");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libunbound-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libunbound8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound-anchor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound-host");
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
    {'release': '11.0', 'prefix': 'libunbound-dev', 'reference': '1.13.1-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libunbound8', 'reference': '1.13.1-1+deb11u2'},
    {'release': '11.0', 'prefix': 'python3-unbound', 'reference': '1.13.1-1+deb11u2'},
    {'release': '11.0', 'prefix': 'unbound', 'reference': '1.13.1-1+deb11u2'},
    {'release': '11.0', 'prefix': 'unbound-anchor', 'reference': '1.13.1-1+deb11u2'},
    {'release': '11.0', 'prefix': 'unbound-host', 'reference': '1.13.1-1+deb11u2'},
    {'release': '12.0', 'prefix': 'libunbound-dev', 'reference': '1.17.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libunbound8', 'reference': '1.17.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'python3-unbound', 'reference': '1.17.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'unbound', 'reference': '1.17.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'unbound-anchor', 'reference': '1.17.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'unbound-host', 'reference': '1.17.1-2+deb12u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libunbound-dev / libunbound8 / python3-unbound / unbound / etc');
}
