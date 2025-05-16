#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4157. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(235610);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2024-3262", "CVE-2025-2545", "CVE-2025-30087");

  script_name(english:"Debian dla-4157 : request-tracker4 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4157 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4157-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/               Santiago Ruano Rincn
    May 08, 2025                                  https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : request-tracker4
    Version        : 4.4.4+dfsg-2+deb11u4
    CVE ID         : CVE-2024-3262 CVE-2025-2545 CVE-2025-30087
    Debian Bug     : 1068452 1104424

    Multiple vulnerabilities have been discovered in Request Tracker, an
    extensible trouble-ticket tracking system, which could result in
    information disclosure, cross-site scripting and use of weak encryption
    for S/MIME emails.

    For Debian 11 bullseye, these problems have been fixed in version
    4.4.4+dfsg-2+deb11u4.

    We recommend that you upgrade your request-tracker4 packages.

    For the detailed security status of request-tracker4 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/request-tracker4

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/request-tracker4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00dbba23");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3262");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-2545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-30087");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/request-tracker4");
  script_set_attribute(attribute:"solution", value:
"Upgrade the request-tracker4 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3262");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-2545");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/08");

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
    {'release': '11.0', 'prefix': 'request-tracker4', 'reference': '4.4.4+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'rt4-apache2', 'reference': '4.4.4+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'rt4-clients', 'reference': '4.4.4+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'rt4-db-mysql', 'reference': '4.4.4+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'rt4-db-postgresql', 'reference': '4.4.4+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'rt4-db-sqlite', 'reference': '4.4.4+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'rt4-doc-html', 'reference': '4.4.4+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'rt4-fcgi', 'reference': '4.4.4+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'rt4-standalone', 'reference': '4.4.4+dfsg-2+deb11u4'}
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
    severity   : SECURITY_NOTE,
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
