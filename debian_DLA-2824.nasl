#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2824. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155658);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/23");

  script_cve_id("CVE-2017-11509");

  script_name(english:"Debian DLA-2824-1 : firebird3.0 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2824
advisory.

  - An authenticated remote attacker can execute arbitrary code in Firebird SQL Server versions 2.5.7 and
    3.0.2 by executing a malformed SQL statement. (CVE-2017-11509)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/firebird3.0");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2824");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-11509");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/firebird3.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade the firebird3.0 packages.

For Debian 9 stretch, this problem has been fixed in version 3.0.1.32609.ds4-14+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11509");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird3.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird3.0-common-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird3.0-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird3.0-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird3.0-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird3.0-server-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird3.0-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfbclient2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libib-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'firebird-dev', 'reference': '3.0.1.32609.ds4-14+deb9u1'},
    {'release': '9.0', 'prefix': 'firebird3.0-common', 'reference': '3.0.1.32609.ds4-14+deb9u1'},
    {'release': '9.0', 'prefix': 'firebird3.0-common-doc', 'reference': '3.0.1.32609.ds4-14+deb9u1'},
    {'release': '9.0', 'prefix': 'firebird3.0-doc', 'reference': '3.0.1.32609.ds4-14+deb9u1'},
    {'release': '9.0', 'prefix': 'firebird3.0-examples', 'reference': '3.0.1.32609.ds4-14+deb9u1'},
    {'release': '9.0', 'prefix': 'firebird3.0-server', 'reference': '3.0.1.32609.ds4-14+deb9u1'},
    {'release': '9.0', 'prefix': 'firebird3.0-server-core', 'reference': '3.0.1.32609.ds4-14+deb9u1'},
    {'release': '9.0', 'prefix': 'firebird3.0-utils', 'reference': '3.0.1.32609.ds4-14+deb9u1'},
    {'release': '9.0', 'prefix': 'libfbclient2', 'reference': '3.0.1.32609.ds4-14+deb9u1'},
    {'release': '9.0', 'prefix': 'libib-util', 'reference': '3.0.1.32609.ds4-14+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firebird-dev / firebird3.0-common / firebird3.0-common-doc / etc');
}
