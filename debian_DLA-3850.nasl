#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3850. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(201168);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/27");

  script_cve_id(
    "CVE-2024-33599",
    "CVE-2024-33600",
    "CVE-2024-33601",
    "CVE-2024-33602"
  );
  script_xref(name:"IAVA", value:"2025-A-0062");

  script_name(english:"Debian dla-3850 : glibc-doc - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3850 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3850-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Adrian Bunk
    June 30, 2024                                 https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : glibc
    Version        : 2.28-10+deb10u4
    CVE ID         : CVE-2024-33599 CVE-2024-33600 CVE-2024-33601 CVE-2024-33602

    Multiple vulnerabilities have been fixed in the Name Service Cache Daemon
    that is built by the GNU C library and shipped in the nscd binary package.

    CVE-2024-33599

        nscd: Stack-based buffer overflow in netgroup cache

    CVE-2024-33600

        nscd: Null pointer crashes after notfound response

    CVE-2024-33601

        nscd: Daemon may terminate on memory allocation failure

    CVE-2024-33602

        nscd: Possible memory corruption

    For Debian 10 buster, these problems have been fixed in version
    2.28-10+deb10u4.

    We recommend that you upgrade your glibc packages.

    For the detailed security status of glibc please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/glibc

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/glibc");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-33599");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-33600");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-33601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-33602");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/glibc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the glibc-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-33599");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:locales-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multiarch-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '10.0', 'prefix': 'glibc-doc', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'glibc-source', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc-bin', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc-dev-bin', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc-l10n', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc6', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc6-amd64', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc6-dbg', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc6-dev', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc6-dev-amd64', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc6-dev-i386', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc6-dev-x32', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc6-i386', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc6-pic', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc6-x32', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'libc6-xen', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'locales', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'locales-all', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'multiarch-support', 'reference': '2.28-10+deb10u4'},
    {'release': '10.0', 'prefix': 'nscd', 'reference': '2.28-10+deb10u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc-doc / glibc-source / libc-bin / libc-dev-bin / libc-l10n / libc6 / etc');
}
