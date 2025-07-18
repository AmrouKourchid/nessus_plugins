#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2877. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156691);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/21");

  script_cve_id("CVE-2019-17545", "CVE-2021-45943");

  script_name(english:"Debian DLA-2877-1 : gdal - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2877 advisory.

  - GDAL through 3.0.1 has a poolDestroy double free in OGRExpatRealloc in ogr/ogr_expat.cpp when the 10MB
    threshold is exceeded. (CVE-2019-17545)

  - GDAL 3.3.0 through 3.4.0 has a heap-based buffer overflow in PCIDSK::CPCIDSKFile::ReadFromFile (called
    from PCIDSK::CPCIDSKSegment::ReadFromFile and PCIDSK::CPCIDSKBinarySegment::CPCIDSKBinarySegment).
    (CVE-2021-45943)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/gdal");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2877");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-17545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45943");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/gdal");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gdal packages.

For Debian 9 stretch, these problems have been fixed in version 2.1.2+dfsg-5+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gdal-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdal-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdal-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdal-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdal20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-gdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-gdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'gdal-bin', 'reference': '2.1.2+dfsg-5+deb9u1'},
    {'release': '9.0', 'prefix': 'libgdal-dev', 'reference': '2.1.2+dfsg-5+deb9u1'},
    {'release': '9.0', 'prefix': 'libgdal-doc', 'reference': '2.1.2+dfsg-5+deb9u1'},
    {'release': '9.0', 'prefix': 'libgdal-java', 'reference': '2.1.2+dfsg-5+deb9u1'},
    {'release': '9.0', 'prefix': 'libgdal-perl', 'reference': '2.1.2+dfsg-5+deb9u1'},
    {'release': '9.0', 'prefix': 'libgdal20', 'reference': '2.1.2+dfsg-5+deb9u1'},
    {'release': '9.0', 'prefix': 'python-gdal', 'reference': '2.1.2+dfsg-5+deb9u1'},
    {'release': '9.0', 'prefix': 'python3-gdal', 'reference': '2.1.2+dfsg-5+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gdal-bin / libgdal-dev / libgdal-doc / libgdal-java / libgdal-perl / etc');
}
