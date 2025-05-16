#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3270. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170055);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2022-44792", "CVE-2022-44793");

  script_name(english:"Debian dla-3270 : libsnmp-base - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3270 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3270-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    January 15, 2023                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : net-snmp
    Version        : 5.7.3+dfsg-5+deb10u4
    CVE ID         : CVE-2022-44792 CVE-2022-44793
    Debian Bug     : 1024020

    menglong2234 discovered NULL pointer exceptions in net-snmp, a suite of
    Simple Network Management Protocol applications, which could could
    result in debian of service.

    CVE-2022-44792

        A remote attacker (with write access) could trigger a NULL
        dereference while handling ipDefaultTTL via a crafted UDP packet.

    CVE-2022-44793

        A remote attacker (with write access) could trigger a NULL
        dereference while handling ipv6IpForwarding via a crafted UDP
        packet.

    For Debian 10 buster, these problems have been fixed in version
    5.7.3+dfsg-5+deb10u4.

    We recommend that you upgrade your net-snmp packages.

    For the detailed security status of net-snmp please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/net-snmp

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/net-snmp");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-44792");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-44793");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/net-snmp");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libsnmp-base packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44793");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp30-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-netsnmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tkmib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libsnmp-base', 'reference': '5.7.3+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'libsnmp-dev', 'reference': '5.7.3+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'libsnmp-perl', 'reference': '5.7.3+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'libsnmp30', 'reference': '5.7.3+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'libsnmp30-dbg', 'reference': '5.7.3+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'python-netsnmp', 'reference': '5.7.3+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'snmp', 'reference': '5.7.3+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'snmpd', 'reference': '5.7.3+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'snmptrapd', 'reference': '5.7.3+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'tkmib', 'reference': '5.7.3+dfsg-5+deb10u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsnmp-base / libsnmp-dev / libsnmp-perl / libsnmp30 / libsnmp30-dbg / etc');
}
