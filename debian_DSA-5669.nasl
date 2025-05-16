#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5669. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(193698);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-27297");

  script_name(english:"Debian dsa-5669 : guix - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has a package installed that is affected by a vulnerability as referenced in the dsa-5669
advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5669-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    April 22, 2024                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : guix
    CVE ID         : CVE-2024-27297

    It was discovered that insufficient restriction of unix daemon sockets
    in the GNU Guix functional package manager could result in sandbox
    bypass.

    For the oldstable distribution (bullseye), this problem has been fixed
    in version 1.2.0-4+deb11u2.

    For the stable distribution (bookworm), this problem has been fixed in
    version 1.4.0-3+deb12u1.

    We recommend that you upgrade your guix packages.

    For the detailed security status of guix please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/guix

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCgAdFiEEtuYvPRKsOElcDakFEMKTtsN8TjYFAmYmEj0ACgkQEMKTtsN8
    TjadOg//QNwxj1LaUW92byZO1DaMWzwnPElHIwwgTUIWj2NCxZQbumPb6PF0AnYq
    n15GcHY1y3jvJ9VnvLI7uns82Gtjqhr9m/sfrDnX/9JPlLBNXTdjQ3/mpECUp6aU
    BvN+kmw4irmsfXqtWR33nrdxID+/mCuDfDHM0Cl64JSbrntqOhpRbkML3DNOdWs0
    h6BeIhFRoGkLLzh2M8U9uyivrLwrlf8ONem4kmn0xtRowc2Y/0GSg/fJIJPwR3/K
    j8FmuydKkm3oVNITr2z2f+b9mzSxXbC7tOgoA6o7Vuxc3Ha7cGn9DojFWKV5DCPv
    VFMKjeos9ELIetmSA/GtSMqTn5rV2QlRWHvUnxtGTyewHsz4j/cXXo5F59f+t2zB
    LZ8aAlzbM5c5/ZVhQVNnuzY8ueaPkOAyFkdawPjSTis0S0KYjgz9/4F8peYNEyJ7
    GUgS2b9aXp3j1dLPKjXDXHXUNL3quemK3aUZCZElgsGN6oHZnOvf/t04jL9BN0/o
    gL7wShs2ZsS/AQ7HRQ+OuYTTcs8patbgitCKI74u8oS/ArrG/U4TfgKhwqFaAICX
    x5cJFreSKzhTQWIhGaxPY73s1zDy5KyLBQjQ67DPbqqYcCC0SwrUFegYrOllORnj
    TLlkkG7vkelx/PxYqzy+YrWeoHt/jdSTR8j5bn1XEYPa/4MZrIg=
    =0oSL
    -----END PGP SIGNATURE-----

    Reply to:
    debian-security-announce@lists.debian.org
    Moritz Muehlenhoff (on-list)
    Moritz Muehlenhoff (off-list)

    Prev by Date:
    [SECURITY] [DSA 5668-1] chromium security update

    Next by Date:
    [SECURITY] [DSA 5670-1] thunderbird security update

    Previous by thread:
    [SECURITY] [DSA 5668-1] chromium security update

    Next by thread:
    [SECURITY] [DSA 5670-1] thunderbird security update

    Index(es):

    Date
    Thread

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/guix");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/guix");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27297");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/guix");
  script_set_attribute(attribute:"solution", value:
"Upgrade the guix packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27297");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:guix");
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
    {'release': '11.0', 'prefix': 'guix', 'reference': '1.2.0-4+deb11u2'},
    {'release': '12.0', 'prefix': 'guix', 'reference': '1.4.0-3+deb12u1'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'guix');
}
