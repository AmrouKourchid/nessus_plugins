#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5369. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(172130);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/14");

  script_cve_id("CVE-2022-38725");

  script_name(english:"Debian DSA-5369-1 : syslog-ng - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5369
advisory.

  - An integer overflow in the RFC3164 parser in One Identity syslog-ng 3.0 through 3.37 allows remote
    attackers to cause a Denial of Service via crafted syslog input that is mishandled by the tcp or network
    function. syslog-ng Premium Edition 7.0.30 and syslog-ng Store Box 6.10.0 are also affected.
    (CVE-2022-38725)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/syslog-ng");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5369");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38725");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/syslog-ng");
  script_set_attribute(attribute:"solution", value:
"Upgrade the syslog-ng packages.

For the stable distribution (bullseye), this problem has been fixed in version 3.28.1-2+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38725");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-add-contextual-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-amqp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-geoip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-getent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-map-value-pairs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-rdkafka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-riemann");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-slog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-smtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-stardate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-stomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:syslog-ng-mod-xml-parser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'syslog-ng', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-core', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-dbg', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-dev', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-add-contextual-data', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-amqp', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-examples', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-extra', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-geoip2', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-getent', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-graphite', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-http', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-map-value-pairs', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-mongodb', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-python', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-rdkafka', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-redis', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-riemann', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-slog', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-smtp', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-snmp', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-sql', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-stardate', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-stomp', 'reference': '3.28.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'syslog-ng-mod-xml-parser', 'reference': '3.28.1-2+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'syslog-ng / syslog-ng-core / syslog-ng-dbg / syslog-ng-dev / etc');
}
