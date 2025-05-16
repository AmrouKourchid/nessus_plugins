#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5638. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(191783);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-24806");

  script_name(english:"Debian dsa-5638 : libuv1 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5638
advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5638-1                   security@debian.org
    https://www.debian.org/security/                     Salvatore Bonaccorso
    March 10, 2024                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : libuv1
    CVE ID         : CVE-2024-24806
    Debian Bug     : 1063484

    It was discovered that the uv_getaddrinfo() function in libuv, an
    asynchronous event notification library, incorrectly truncated certain
    hostnames, which may result in bypass of security measures on internal
    APIs or SSRF attacks.

    For the oldstable distribution (bullseye), this problem has been fixed
    in version 1.40.0-2+deb11u1.

    For the stable distribution (bookworm), this problem has been fixed in
    version 1.44.2-1+deb12u1.

    We recommend that you upgrade your libuv1 packages.

    For the detailed security status of libuv1 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libuv1

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQKTBAEBCgB9FiEERkRAmAjBceBVMd3uBUy48xNDz0QFAmXtrrFfFIAAAAAALgAo
    aXNzdWVyLWZwckBub3RhdGlvbnMub3BlbnBncC5maWZ0aGhvcnNlbWFuLm5ldDQ2
    NDQ0MDk4MDhDMTcxRTA1NTMxRERFRTA1NENCOEYzMTM0M0NGNDQACgkQBUy48xND
    z0TOBw//UDY7qqzhavYjzvVxQ6ka9PGfBLJcRXhMjpwH5JxR6T0KOqCQkasoXCxm
    NTSzczr0zrtU4Hdtv6tb/E5QfemTpdEfMOtuuKxhQ3jrQNjnqtfDD5ouomrckxMc
    PtB3SsJ0e1BV97ORDEqrym39VQTIaVgxdZwXU5/mcqaboZx8uxv8XjaDURhAU1eY
    z5PDno6bTg/zL7bSSugTnxSPHwokv4FICxaG8rR6y6drbI7hndsx+LL+sXs426O8
    xDzro+deanl3i9kdXxQujhTxJA+7vUTeaCl8rLFs7kOyNxDbCVADYc+Cc0h8Z0xn
    v/xNDYkIMprGcUx2QgW9mwfDgKGxDVtltPwb6oIBsKzrYBF/gVUqM5aym3VquS8n
    +lL7+uA0ZHKMxeQRrCtHCIoDUAhjVarQPqbxIX92tftSIRHU7e8Qfmyo7PdbPs9U
    C4zUUwIwQ6UtRR8OWIKE8IFa+BRxL2/3KCDjDvpK60VUfanRqdF7zcvifFQMw9mq
    J/s/IIY6Unhvk9/6QSKrNiaLnFBOVBZ4E4A5OU6W1KAKvixlH8bmv0XCgrlDr2fx
    /7+Xn8wNA86qPAd9/t6DAVzyjdlis+P6LYzAfrAguWQQS0xkDW+5OQqV3wyKvK1m
    9PRJK4vfmiX5kw+VclGbJM4ToaKOLbSlns/QNhHuRw2RDem0/+s=
    =ai3N
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libuv1");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-24806");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/libuv1");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libuv1");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libuv1 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24806");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuv1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuv1-dev");
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
    {'release': '11.0', 'prefix': 'libuv1', 'reference': '1.40.0-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libuv1-dev', 'reference': '1.40.0-2+deb11u1'},
    {'release': '12.0', 'prefix': 'libuv1', 'reference': '1.44.2-1+deb12u1'},
    {'release': '12.0', 'prefix': 'libuv1-dev', 'reference': '1.44.2-1+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libuv1 / libuv1-dev');
}
