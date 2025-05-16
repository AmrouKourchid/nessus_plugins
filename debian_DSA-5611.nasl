#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5611. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(189829);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2023-6246", "CVE-2023-6779", "CVE-2023-6780");

  script_name(english:"Debian dsa-5611 : glibc-doc - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5611 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5611-1                   security@debian.org
    https://www.debian.org/security/                     Salvatore Bonaccorso
    January 30, 2024                      https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : glibc
    CVE ID         : CVE-2023-6246 CVE-2023-6779 CVE-2023-6780

    The Qualys Research Labs discovered several vulnerabilities in the GNU C
    Library's __vsyslog_internal() function (called by syslog() and
    vsyslog()). A heap-based buffer overflow (CVE-2023-6246), an off-by-one
    heap overflow (CVE-2023-6779) and an integer overflow (CVE-2023-6780)
    can be exploited for privilege escalation or denial of service.

    Details can be found in the Qualys advisory at
    https://www.qualys.com/2024/01/30/syslog

    Additionally a memory corruption was discovered in the glibc's qsort()
    function, due to missing bounds check and when called by a program
    with a non-transitive comparison function and a large number of
    attacker-controlled elements. As the use of qsort() with a
    non-transitive comparison function is undefined according to POSIX and
    ISO C standards, this is not considered a vulnerability in the glibc
    itself. However the qsort() implementation was hardened against
    misbehaving callers.

    Details can be found in the Qualys advisory at
    https://www.qualys.com/2024/01/30/qsort

    For the stable distribution (bookworm), these problems have been fixed in
    version 2.36-9+deb12u4.

    We recommend that you upgrade your glibc packages.

    For the detailed security status of glibc please refer to its security
    tracker page at:
    https://security-tracker.debian.org/tracker/glibc

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQKTBAEBCgB9FiEERkRAmAjBceBVMd3uBUy48xNDz0QFAmW5P2BfFIAAAAAALgAo
    aXNzdWVyLWZwckBub3RhdGlvbnMub3BlbnBncC5maWZ0aGhvcnNlbWFuLm5ldDQ2
    NDQ0MDk4MDhDMTcxRTA1NTMxRERFRTA1NENCOEYzMTM0M0NGNDQACgkQBUy48xND
    z0TCeQ//VD4TdNtM/wBBMsQ2/RTFVO81yT6ZJ2jxy8v2h9ZZtsBhi1kMP+P4E2pC
    yAl+8TGZpKCbMqifecV85Z9674aUfEFrqju8E1Mt1kp63MTmagJvPuZg318hjMRg
    byve8v9nMJjpAotbetz5TesUX3eZeWbkAyqd45vg3g40lIyJHusKra5XEmAxflEB
    8zFwZhwWVOZ7cIH2sbsRFprgPcz5YYKAvUEfVWQxikWaN+7XGNKzue6Ar0pkHHGd
    reLUTnGDv4NMr1Y7JLMau/nIO2JXvl7V2+EefFw02/vmRPovz4ZtmWek3vc2DRl9
    JfGEIOkMpbxPgp0dZ2AyKjOEIpIutvGqzLm53MkcajvVlVAMyPPj25rgytaK+07T
    RS+oP77Bw+pDjRu1PpyCDRWIOCJmqP8esyq5IfMuLDBYPT8JvOyq2Iy/q5U+OvXL
    nYzvNXfqIkencR0Sd83aRGho6vWSy89mJEWhvMhjYmriJz7ipQo6t+FZb2Jq23wJ
    pXTcWz5ljtuSQRmf2A98InQsyg1sBVj3dH/8uYEl5f58TvF06SL6vJwtxJED1vLk
    LR9D1G2zyoJf6PFPMj+qtgdZKxYPX6Zr3nJTNRwM74Z8AYQEcuczWm2vhq78ipPi
    AyAjNDzU/MPUaDTKeyjS04XD3tyOD3RDPWDjKhV/BiKFuAjuqro=
    =Zs+W
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/glibc");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6246");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6779");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6780");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/glibc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the glibc-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6246");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-devtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-mips32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-mips64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-mipsn32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-mips32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-mips64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-mipsn32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:locales-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nscd");
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
    {'release': '12.0', 'prefix': 'glibc-doc', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'glibc-source', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc-bin', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc-dev-bin', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc-devtools', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc-l10n', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-amd64', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-dbg', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-dev', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-dev-amd64', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-dev-i386', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-dev-mips32', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-dev-mips64', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-dev-mipsn32', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-dev-s390', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-dev-x32', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-i386', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-mips32', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-mips64', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-mipsn32', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-s390', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-udeb', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'libc6-x32', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'locales', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'locales-all', 'reference': '2.36-9+deb12u4'},
    {'release': '12.0', 'prefix': 'nscd', 'reference': '2.36-9+deb12u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc-doc / glibc-source / libc-bin / libc-dev-bin / libc-devtools / etc');
}
