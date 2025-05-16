#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3907. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(207951);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id("CVE-2021-36690", "CVE-2023-7104");
  script_xref(name:"IAVA", value:"2024-A-0003-S");

  script_name(english:"Debian dla-3907 : lemon - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3907 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3907-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Adrian Bunk
    September 30, 2024                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : sqlite3
    Version        : 3.34.1-3+deb11u1
    CVE ID         : CVE-2021-36690 CVE-2023-7104

    Two vulnerabilities have been fixed in the SQLite database.

    CVE-2021-36690

        Expert extension segfault

    CVE-2023-7104

        Session extension buffer overread

    For Debian 11 bullseye, these problems have been fixed in version
    3.34.1-3+deb11u1.

    We recommend that you upgrade your sqlite3 packages.

    For the detailed security status of sqlite3 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/sqlite3

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/sqlite3");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36690");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-7104");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/sqlite3");
  script_set_attribute(attribute:"solution", value:
"Upgrade the lemon packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36690");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-7104");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sqlite3-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'lemon', 'reference': '3.34.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'libsqlite3-0', 'reference': '3.34.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'libsqlite3-dev', 'reference': '3.34.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'libsqlite3-tcl', 'reference': '3.34.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'sqlite3', 'reference': '3.34.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'sqlite3-doc', 'reference': '3.34.1-3+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lemon / libsqlite3-0 / libsqlite3-dev / libsqlite3-tcl / sqlite3 / etc');
}
