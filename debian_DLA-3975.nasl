#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3975. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(211971);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/29");

  script_cve_id("CVE-2023-48795", "CVE-2023-51713", "CVE-2024-48651");

  script_name(english:"Debian dla-3975 : proftpd-basic - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3975 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3975-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    November 29, 2024                             https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : proftpd-dfsg
    Version        : 1.3.7a+dfsg-12+deb11u3
    CVE ID         : CVE-2023-48795 CVE-2023-51713 CVE-2024-48651
    Debian Bug     : 1082326

    ProFTPD a popular FTP server was affected by multiple
    vulnerabilities.

    CVE-2023-48795

        The SSH transport protocol and variant like SFTP protocol used by
        ProFTPD allowed remote attackers to bypass integrity checks
        such that some packets are omitted (from the extension negotiation message),
        and a client and server may consequently end up with a connection
        for which some security features have been downgraded or disabled,
        aka a Terrapin attack.

    CVE-2023-51713

        make_ftp_cmd function has a one-byte out-of-bounds read,
        because of mishandling of quote/backslash semantics.

    CVE-2024-48651

        In proftpd with mod_sftp and mod_sql, an user with
        no supplemental groups will incorrectly inherit supplemental
        groups from the parent process. Thhis behavior resulted in users gaining supplemental
        membership in nogroup, or depending of version root group (GID=0).

    For Debian 11 bullseye, these problems have been fixed in version
    1.3.7a+dfsg-12+deb11u3.

    We recommend that you upgrade your proftpd-dfsg packages.

    For the detailed security status of proftpd-dfsg please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/proftpd-dfsg

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/proftpd-dfsg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a98522a3");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-48795");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-51713");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-48651");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/proftpd-dfsg");
  script_set_attribute(attribute:"solution", value:
"Upgrade the proftpd-basic packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-48795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-wrap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'proftpd-basic', 'reference': '1.3.7a+dfsg-12+deb11u3'},
    {'release': '11.0', 'prefix': 'proftpd-core', 'reference': '1.3.7a+dfsg-12+deb11u3'},
    {'release': '11.0', 'prefix': 'proftpd-dev', 'reference': '1.3.7a+dfsg-12+deb11u3'},
    {'release': '11.0', 'prefix': 'proftpd-doc', 'reference': '1.3.7a+dfsg-12+deb11u3'},
    {'release': '11.0', 'prefix': 'proftpd-mod-crypto', 'reference': '1.3.7a+dfsg-12+deb11u3'},
    {'release': '11.0', 'prefix': 'proftpd-mod-geoip', 'reference': '1.3.7a+dfsg-12+deb11u3'},
    {'release': '11.0', 'prefix': 'proftpd-mod-ldap', 'reference': '1.3.7a+dfsg-12+deb11u3'},
    {'release': '11.0', 'prefix': 'proftpd-mod-mysql', 'reference': '1.3.7a+dfsg-12+deb11u3'},
    {'release': '11.0', 'prefix': 'proftpd-mod-odbc', 'reference': '1.3.7a+dfsg-12+deb11u3'},
    {'release': '11.0', 'prefix': 'proftpd-mod-pgsql', 'reference': '1.3.7a+dfsg-12+deb11u3'},
    {'release': '11.0', 'prefix': 'proftpd-mod-snmp', 'reference': '1.3.7a+dfsg-12+deb11u3'},
    {'release': '11.0', 'prefix': 'proftpd-mod-sqlite', 'reference': '1.3.7a+dfsg-12+deb11u3'},
    {'release': '11.0', 'prefix': 'proftpd-mod-wrap', 'reference': '1.3.7a+dfsg-12+deb11u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'proftpd-basic / proftpd-core / proftpd-dev / proftpd-doc / etc');
}
