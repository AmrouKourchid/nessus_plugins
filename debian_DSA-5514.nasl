#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5514. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(182473);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2023-4527", "CVE-2023-4806", "CVE-2023-4911");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/12");

  script_name(english:"Debian DSA-5514-1 : glibc - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5514 advisory.

    The Qualys Research Labs discovered a buffer overflow in the dynamic loader's processing of the
    GLIBC_TUNABLES environment variable. An attacker can exploit this flaw for privilege escalation. Details
    can be found in the Qualys advisory at https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables-
    local-privilege-escalation-glibc-ld-so.txt For the oldstable distribution (bullseye), this problem has
    been fixed in version 2.31-13+deb11u7. For the stable distribution (bookworm), this problem has been fixed
    in version 2.36-9+deb12u3. This update includes fixes for CVE-2023-4527 and CVE-2023-4806 originally
    planned for the upcoming bookworm point release. We recommend that you upgrade your glibc packages. For
    the detailed security status of glibc please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/glibc

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/glibc");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5514");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4527");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4806");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4911");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/glibc");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/glibc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the glibc packages.

For the stable distribution (bookworm), this problem has been fixed in version 2.36-9+deb12u3.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4911");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Glibc Tunables Privilege Escalation CVE-2023-4911 (aka Looney Tunables)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/03");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:locales-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'glibc-doc', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'glibc-source', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc-bin', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc-dev-bin', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc-devtools', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc-l10n', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-amd64', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-dbg', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-dev', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-dev-amd64', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-dev-i386', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-dev-mips32', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-dev-mips64', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-dev-mipsn32', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-dev-s390', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-dev-x32', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-i386', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-mips32', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-mips64', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-mipsn32', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-s390', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-udeb', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-x32', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'libc6-xen', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'locales', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'locales-all', 'reference': '2.31-13+deb11u7'},
    {'release': '11.0', 'prefix': 'nscd', 'reference': '2.31-13+deb11u7'},
    {'release': '12.0', 'prefix': 'glibc-doc', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'glibc-source', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc-bin', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc-dev-bin', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc-devtools', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc-l10n', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-amd64', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-dbg', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-dev', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-dev-amd64', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-dev-i386', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-dev-mips32', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-dev-mips64', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-dev-mipsn32', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-dev-s390', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-dev-x32', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-i386', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-mips32', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-mips64', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-mipsn32', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-s390', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-udeb', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'libc6-x32', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'locales', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'locales-all', 'reference': '2.36-9+deb12u3'},
    {'release': '12.0', 'prefix': 'nscd', 'reference': '2.36-9+deb12u3'}
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
