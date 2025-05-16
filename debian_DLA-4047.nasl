#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4047. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(215163);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/09");

  script_cve_id("CVE-2021-3621", "CVE-2023-3758");

  script_name(english:"Debian dla-4047 : libipa-hbac-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4047 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4047-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    February 09, 2025                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : sssd
    Version        : 2.4.1-2+deb11u1
    CVE ID         : CVE-2021-3621 CVE-2023-3758
    Debian Bug     : 992710 1070369

    Vulnerabilities were found in sssd, a set of daemons to manage access to
    remote directories and authentication mechanisms, which could lead to
    privilege escalation.

    CVE-2021-3621

        It was discovered that the sssctl(8) command was vulnerable to shell
        command injection via the logs-fetch and cache-expire
        subcommands.

        This flaw could allows an attacker to trick the root user into
        running a specially crafted sssctl(8) command, such as via sudo, in
        order to gain root privileges.

    CVE-2023-3758

        A race condition flaw was found in SSSD where the GPO policy is not
        consistently applied for authenticated users.  This may lead to
        improper authorization issues, granting access to resources
        inappropriately.

    For Debian 11 bullseye, these problems have been fixed in version
    2.4.1-2+deb11u1.

    We recommend that you upgrade your sssd packages.

    For the detailed security status of sssd please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/sssd

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/sssd");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3621");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3758");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/sssd");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libipa-hbac-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3621");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libipa-hbac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libipa-hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-certmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-certmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-idmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-nss-idmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-nss-idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-simpleifp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-simpleifp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-sssd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libipa-hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libsss-nss-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ad-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'libipa-hbac-dev', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libipa-hbac0', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libnss-sss', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libpam-sss', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsss-certmap-dev', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsss-certmap0', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsss-idmap-dev', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsss-idmap0', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsss-nss-idmap-dev', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsss-nss-idmap0', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsss-simpleifp-dev', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsss-simpleifp0', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsss-sudo', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libwbclient-sssd', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libwbclient-sssd-dev', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'python3-libipa-hbac', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'python3-libsss-nss-idmap', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'python3-sss', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sssd', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sssd-ad', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sssd-ad-common', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sssd-common', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sssd-dbus', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sssd-ipa', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sssd-kcm', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sssd-krb5', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sssd-krb5-common', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sssd-ldap', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sssd-proxy', 'reference': '2.4.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'sssd-tools', 'reference': '2.4.1-2+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libipa-hbac-dev / libipa-hbac0 / libnss-sss / libpam-sss / etc');
}
