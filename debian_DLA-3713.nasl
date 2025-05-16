#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3713. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(189267);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_name(english:"Debian dla-3713 : libcppunit-subunit-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3713
advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3713-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    January 21, 2024                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : subunit
    Version        : 1.3.0-1+deb10u1

    Subunit, a testing component for a few OpenStack projects, was
    affected by a major bug. This bug renders building and testing
    security updates of OpenStack components difficult, due to
    random crashes during building or testing, particularly
    keystone component.

    For Debian 10 buster, this problem has been fixed in version
    1.3.0-1+deb10u1.

    We recommend that you upgrade your subunit packages.

    For the detailed security status of subunit please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/subunit

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/subunit");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/subunit");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libcppunit-subunit-dev packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcppunit-subunit-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcppunit-subunit0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsubunit-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsubunit-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsubunit0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-subunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-subunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subunit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libcppunit-subunit-dev', 'reference': '1.3.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libcppunit-subunit0', 'reference': '1.3.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libsubunit-dev', 'reference': '1.3.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libsubunit-perl', 'reference': '1.3.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libsubunit0', 'reference': '1.3.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'python-subunit', 'reference': '1.3.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-subunit', 'reference': '1.3.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'subunit', 'reference': '1.3.0-1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcppunit-subunit-dev / libcppunit-subunit0 / libsubunit-dev / etc');
}
