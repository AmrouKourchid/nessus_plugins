#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4000. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(213318);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/21");

  script_cve_id("CVE-2021-32839", "CVE-2023-30608", "CVE-2024-4340");

  script_name(english:"Debian dla-4000 : python-sqlparse-doc - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4000 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4000-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    December 21, 2024                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : sqlparse
    Version        : 0.4.1-1+deb11u1
    CVE ID         : CVE-2021-32839 CVE-2023-30608 CVE-2024-4340
    Debian Bug     : 994841 1034615 1070148

    Multiple vulnerabilities were found in sqlparse, a non-validating SQL
    parser for Python, which can lead to Denial of Service.

    CVE-2021-32839

        Erik Krogh Kristensen discovered that the StripComments filter
        contains a regular expression that is vulnerable to ReDOS (Regular
        Expression Denial of Service).  The regular expression may cause
        exponential backtracking on strings containing many repetitions of
        '\r\n' in SQL comments.

    CVE-2023-30608

        Erik Krogh Kristensen discovered that the Parser contains a regular
        expression that is vulnerable to ReDOS (Regular Expression Denial of
        Service).

    CVE-2024-4340

        Uriya Yavniely discovered that passing a heavily nested list to
        sqlparse.parse() may raise a RecursionError exception.  A generic
        SQLParseError is now raised instead.

    For Debian 11 bullseye, these problems have been fixed in version
    0.4.1-1+deb11u1.

    We recommend that you upgrade your sqlparse packages.

    For the detailed security status of sqlparse please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/sqlparse

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/sqlparse");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32839");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-30608");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-4340");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/sqlparse");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python-sqlparse-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32839");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-30608");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-sqlparse-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sqlformat");
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
    {'release': '11.0', 'prefix': 'python-sqlparse-doc', 'reference': '0.4.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'python3-sqlparse', 'reference': '0.4.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'sqlformat', 'reference': '0.4.1-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-sqlparse-doc / python3-sqlparse / sqlformat');
}
