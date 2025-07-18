#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5542. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(184064);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/14");

  script_cve_id("CVE-2023-41259", "CVE-2023-41260");

  script_name(english:"Debian DSA-5542-1 : request-tracker4 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5542 advisory.

  - Request Tracker reports: CVE-2023-41259 SECURITY: RT is vulnerable to unvalidated email headers in
    incoming email and the mail-gateway REST interface. CVE-2023-41260 SECURITY: RT is vulnerable to
    information leakage via response messages returned from requests sent via the mail-gateway REST interface.
    CVE-2023-45024 SECURITY: RT 5.0 is vulnerable to information leakage via transaction searches made by
    authenticated users in the transaction query builder. (CVE-2023-41259, CVE-2023-41260)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1054516");
  # https://security-tracker.debian.org/tracker/source-package/request-tracker4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00dbba23");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5542");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-41259");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-41260");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/request-tracker4");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/request-tracker4");
  script_set_attribute(attribute:"solution", value:
"Upgrade the request-tracker4 packages.

For the stable distribution (bookworm), these problems have been fixed in version 4.4.6+dfsg-1.1+deb12u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41260");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:request-tracker4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-db-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-db-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-db-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-fcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-standalone");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'request-tracker4', 'reference': '4.4.4+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'rt4-apache2', 'reference': '4.4.4+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'rt4-clients', 'reference': '4.4.4+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'rt4-db-mysql', 'reference': '4.4.4+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'rt4-db-postgresql', 'reference': '4.4.4+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'rt4-db-sqlite', 'reference': '4.4.4+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'rt4-doc-html', 'reference': '4.4.4+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'rt4-fcgi', 'reference': '4.4.4+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'rt4-standalone', 'reference': '4.4.4+dfsg-2+deb11u3'},
    {'release': '12.0', 'prefix': 'request-tracker4', 'reference': '4.4.6+dfsg-1.1+deb12u1'},
    {'release': '12.0', 'prefix': 'rt4-apache2', 'reference': '4.4.6+dfsg-1.1+deb12u1'},
    {'release': '12.0', 'prefix': 'rt4-clients', 'reference': '4.4.6+dfsg-1.1+deb12u1'},
    {'release': '12.0', 'prefix': 'rt4-db-mysql', 'reference': '4.4.6+dfsg-1.1+deb12u1'},
    {'release': '12.0', 'prefix': 'rt4-db-postgresql', 'reference': '4.4.6+dfsg-1.1+deb12u1'},
    {'release': '12.0', 'prefix': 'rt4-db-sqlite', 'reference': '4.4.6+dfsg-1.1+deb12u1'},
    {'release': '12.0', 'prefix': 'rt4-doc-html', 'reference': '4.4.6+dfsg-1.1+deb12u1'},
    {'release': '12.0', 'prefix': 'rt4-fcgi', 'reference': '4.4.6+dfsg-1.1+deb12u1'},
    {'release': '12.0', 'prefix': 'rt4-standalone', 'reference': '4.4.6+dfsg-1.1+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'request-tracker4 / rt4-apache2 / rt4-clients / rt4-db-mysql / etc');
}
