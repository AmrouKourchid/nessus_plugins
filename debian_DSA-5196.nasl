#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5196. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(163651);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/17");

  script_cve_id("CVE-2020-13692", "CVE-2022-21724", "CVE-2022-26520");

  script_name(english:"Debian DSA-5196-1 : libpgjava - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5196 advisory.

  - PostgreSQL JDBC Driver (aka PgJDBC) before 42.2.13 allows XXE. (CVE-2020-13692)

  - pgjdbc is the offical PostgreSQL JDBC Driver. A security hole was found in the jdbc driver for postgresql
    database while doing security research. The system using the postgresql library will be attacked when
    attacker control the jdbc url or properties. pgjdbc instantiates plugin instances based on class names
    provided via `authenticationPluginClassName`, `sslhostnameverifier`, `socketFactory`, `sslfactory`,
    `sslpasswordcallback` connection properties. However, the driver did not verify if the class implements
    the expected interface before instantiating the class. This can lead to code execution loaded via
    arbitrary classes. Users using plugins are advised to upgrade. There are no known workarounds for this
    issue. (CVE-2022-21724)

  - ** DISPUTED ** In pgjdbc before 42.3.3, an attacker (who controls the jdbc URL or properties) can call
    java.util.logging.FileHandler to write to arbitrary files through the loggerFile and loggerLevel
    connection properties. An example situation is that an attacker could create an executable JSP file under
    a Tomcat web root. NOTE: the vendor's position is that there is no pgjdbc vulnerability; instead, it is a
    vulnerability for any application to use the pgjdbc driver with untrusted connection properties.
    (CVE-2022-26520)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=962828");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libpgjava");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5196");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-13692");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21724");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26520");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libpgjava");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libpgjava");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libpgjava packages.

For the stable distribution (bullseye), these problems have been fixed in version 42.2.15-1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26520");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostgresql-jdbc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostgresql-jdbc-java-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libpostgresql-jdbc-java', 'reference': '42.2.5-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libpostgresql-jdbc-java-doc', 'reference': '42.2.5-2+deb10u1'},
    {'release': '11.0', 'prefix': 'libpostgresql-jdbc-java', 'reference': '42.2.15-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libpostgresql-jdbc-java-doc', 'reference': '42.2.15-1+deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpostgresql-jdbc-java / libpostgresql-jdbc-java-doc');
}
