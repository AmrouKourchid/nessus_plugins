#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5554. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(185521);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2023-5868",
    "CVE-2023-5869",
    "CVE-2023-5870",
    "CVE-2023-39417"
  );
  script_xref(name:"IAVB", value:"2023-B-0088-S");

  script_name(english:"Debian DSA-5554-1 : postgresql-13 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5554 advisory.

    Several vulnerabilities have been discovered in the PostgreSQL database system. CVE-2023-5868 Jingzhou Fu
    discovered a memory disclosure flaw in aggregate function calls. CVE-2023-5869 Pedro Gallegos reported
    integer overflow flaws resulting in buffer overflows in the array modification functions. CVE-2023-5870
    Hemanth Sandrana and Mahendrakar Srinivasarao reported that the pg_cancel_backend role can signal certain
    superuser processes, potentially resulting in denial of service. CVE-2023-39417 Micah Gate, Valerie
    Woolard, Tim Carey-Smith, and Christoph Berg reported that an extension script using @substitutions@
    within quoting may allow to perform an SQL injection for an attacker having database-level CREATE
    privileges. For the oldstable distribution (bullseye), these problems have been fixed in version
    13.13-0+deb11u1. We recommend that you upgrade your postgresql-13 packages. For the detailed security
    status of postgresql-13 please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/postgresql-13

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/postgresql-13
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1964ded4");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5554");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39417");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-5868");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-5869");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-5870");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/postgresql-13");
  script_set_attribute(attribute:"solution", value:
"Upgrade the postgresql-13 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5869");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg-compat3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpgtypes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-client-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-doc-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plperl-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plpython3-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-pltcl-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-server-dev-13");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libecpg-compat3', 'reference': '13.13-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libecpg-dev', 'reference': '13.13-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libecpg6', 'reference': '13.13-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libpgtypes3', 'reference': '13.13-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libpq-dev', 'reference': '13.13-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libpq5', 'reference': '13.13-0+deb11u1'},
    {'release': '11.0', 'prefix': 'postgresql-13', 'reference': '13.13-0+deb11u1'},
    {'release': '11.0', 'prefix': 'postgresql-client-13', 'reference': '13.13-0+deb11u1'},
    {'release': '11.0', 'prefix': 'postgresql-doc-13', 'reference': '13.13-0+deb11u1'},
    {'release': '11.0', 'prefix': 'postgresql-plperl-13', 'reference': '13.13-0+deb11u1'},
    {'release': '11.0', 'prefix': 'postgresql-plpython3-13', 'reference': '13.13-0+deb11u1'},
    {'release': '11.0', 'prefix': 'postgresql-pltcl-13', 'reference': '13.13-0+deb11u1'},
    {'release': '11.0', 'prefix': 'postgresql-server-dev-13', 'reference': '13.13-0+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libecpg-compat3 / libecpg-dev / libecpg6 / libpgtypes3 / libpq-dev / etc');
}
