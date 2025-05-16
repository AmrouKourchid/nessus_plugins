#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2835. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155738);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2019-17041", "CVE-2019-17042");

  script_name(english:"Debian DLA-2835-1 : rsyslog - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2835 advisory.

    Two heap overflows were fixed in the rsyslog logging daemon. CVE-2019-17041 Heap overflow in the AIX
    message parser. CVE-2019-17042 Heap overflow in the Cisco log message parser. For Debian 9 stretch, these
    problems have been fixed in version 8.24.0-1+deb9u1. We recommend that you upgrade your rsyslog packages.
    For the detailed security status of rsyslog please refer to its security tracker page at:
    https://security-tracker.debian.org/tracker/rsyslog Further information about Debian LTS security
    advisories, how to apply these updates to your system and frequently asked questions can be found at:
    https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=942065");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/rsyslog");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2835");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-17041");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-17042");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/rsyslog");
  script_set_attribute(attribute:"solution", value:
"Upgrade the rsyslog packages.

For Debian 9 stretch, these problems have been fixed in version 8.24.0-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-czmq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-hiredis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-kafka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(9)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'rsyslog', 'reference': '8.24.0-1+deb9u1'},
    {'release': '9.0', 'prefix': 'rsyslog-czmq', 'reference': '8.24.0-1+deb9u1'},
    {'release': '9.0', 'prefix': 'rsyslog-elasticsearch', 'reference': '8.24.0-1+deb9u1'},
    {'release': '9.0', 'prefix': 'rsyslog-gnutls', 'reference': '8.24.0-1+deb9u1'},
    {'release': '9.0', 'prefix': 'rsyslog-gssapi', 'reference': '8.24.0-1+deb9u1'},
    {'release': '9.0', 'prefix': 'rsyslog-hiredis', 'reference': '8.24.0-1+deb9u1'},
    {'release': '9.0', 'prefix': 'rsyslog-kafka', 'reference': '8.24.0-1+deb9u1'},
    {'release': '9.0', 'prefix': 'rsyslog-mongodb', 'reference': '8.24.0-1+deb9u1'},
    {'release': '9.0', 'prefix': 'rsyslog-mysql', 'reference': '8.24.0-1+deb9u1'},
    {'release': '9.0', 'prefix': 'rsyslog-pgsql', 'reference': '8.24.0-1+deb9u1'},
    {'release': '9.0', 'prefix': 'rsyslog-relp', 'reference': '8.24.0-1+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rsyslog / rsyslog-czmq / rsyslog-elasticsearch / rsyslog-gnutls / etc');
}
