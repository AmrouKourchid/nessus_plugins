#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5604. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(189387);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2024-20918",
    "CVE-2024-20919",
    "CVE-2024-20921",
    "CVE-2024-20926",
    "CVE-2024-20945",
    "CVE-2024-20952"
  );

  script_name(english:"Debian dsa-5604 : openjdk-11-dbg - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5604 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5604-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    January 23, 2024                      https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : openjdk-11
    CVE ID         : CVE-2024-20918 CVE-2024-20919 CVE-2024-20921 CVE-2024-20926
                     CVE-2024-20945 CVE-2024-20952

    Several vulnerabilities have been discovered in the OpenJDK Java runtime,
    which may result in side channel attacks, leaking sensitive data to log
    files, denial of service or bypass of sandbox restrictions.

    For the oldstable distribution (bullseye), these problems have been fixed
    in version 11.0.22+7-1~deb11u1.

    We recommend that you upgrade your openjdk-11 packages.

    For the detailed security status of openjdk-11 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/openjdk-11

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCgAdFiEEtuYvPRKsOElcDakFEMKTtsN8TjYFAmWwM5UACgkQEMKTtsN8
    TjbmKBAAvEmFMe7zYi8hPaIwWVkgA903gIFGrRFTTA625pefdI5XyqHeXffqNa9d
    gdHnXCs3LZd/9MrO6sJ/hEeiT8sy2ib/SwM5JIQDoz2tK/1YIpZpCPffbsKuJN7u
    EaoSJX1fXsoBUI6y7FZecJZPdbMuLZTc9NOwU3SKjsXn98wgr8s6R7st+22m8wNa
    t4a5dMwp7SeGPNy8o25l+Ps0aYA9lz3xsXJXkAmoh+3+6H79UD8T6nlXkwF98BqD
    NtedI2ZFKckCJUzE+bAIWKx8e1pZSDeif8d10H+rO7y6DikV9JJ9+Q6V9yRmGqfS
    v1/Hs8+BVEIlX/XuXrbrQCRQYpIEhR2IytlpqKsV+RnSGZXITff+xNiA8JDCaRd3
    9R/af4VUAuLbN0G4wos1UBGVtuDqq8zKF9JHAWs1/OhV5BBRlQVumP0i21Aor31s
    XypJGK7i9ggDpJDNFCRbWGP/1ckvRt4qk5g36WtBJaLZLovOQq+0uhIXsA2u5Tz+
    FLffJUshqkfWvXP/ovckf12ka4w7B7HsqusQM7yJQTaKqAvM7GaAOxK/TMN516zH
    XJPnJuK1hDK1C4c+87avnWRz01tbZuGQl6Aviauqvwazr8pmMqBXpO+GqI9Zya4S
    +d931oP/6HDBGsHa0J1kiVtZ8Bf9jj7uDxmv6nKd/iOQSJCNapQ=
    =lPGw
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openjdk-11");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-20918");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-20919");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-20921");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-20926");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-20945");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-20952");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/openjdk-11");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openjdk-11-dbg packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20952");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'openjdk-11-dbg', 'reference': '11.0.22+7-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-demo', 'reference': '11.0.22+7-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-doc', 'reference': '11.0.22+7-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-jdk', 'reference': '11.0.22+7-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-jdk-headless', 'reference': '11.0.22+7-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-jre', 'reference': '11.0.22+7-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-jre-headless', 'reference': '11.0.22+7-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-jre-zero', 'reference': '11.0.22+7-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-source', 'reference': '11.0.22+7-1~deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjdk-11-dbg / openjdk-11-demo / openjdk-11-doc / openjdk-11-jdk / etc');
}
