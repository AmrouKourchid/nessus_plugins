#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5111. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159466);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/03");

  script_cve_id("CVE-2018-25032");

  script_name(english:"Debian DSA-5111-1 : zlib - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5111
advisory.

  - zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many
    distant matches. (CVE-2018-25032)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1008265");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/zlib");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5111");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-25032");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/zlib");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/zlib");
  script_set_attribute(attribute:"solution", value:
"Upgrade the zlib packages.

For the stable distribution (bullseye), this problem has been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-25032");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib32z1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib32z1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib64z1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib64z1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libn32z1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libn32z1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zlib1g");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zlib1g-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zlib1g-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zlib1g-udeb");
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
    {'release': '10.0', 'prefix': 'lib32z1', 'reference': '1:1.2.11.dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'lib32z1-dev', 'reference': '1:1.2.11.dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'lib64z1', 'reference': '1:1.2.11.dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'lib64z1-dev', 'reference': '1:1.2.11.dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libn32z1', 'reference': '1:1.2.11.dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libn32z1-dev', 'reference': '1:1.2.11.dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'zlib1g', 'reference': '1:1.2.11.dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'zlib1g-dbg', 'reference': '1:1.2.11.dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'zlib1g-dev', 'reference': '1:1.2.11.dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'zlib1g-udeb', 'reference': '1:1.2.11.dfsg-1+deb10u1'},
    {'release': '11.0', 'prefix': 'lib32z1', 'reference': '1:1.2.11.dfsg-2+deb11u1'},
    {'release': '11.0', 'prefix': 'lib32z1-dev', 'reference': '1:1.2.11.dfsg-2+deb11u1'},
    {'release': '11.0', 'prefix': 'lib64z1', 'reference': '1:1.2.11.dfsg-2+deb11u1'},
    {'release': '11.0', 'prefix': 'lib64z1-dev', 'reference': '1:1.2.11.dfsg-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libn32z1', 'reference': '1:1.2.11.dfsg-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libn32z1-dev', 'reference': '1:1.2.11.dfsg-2+deb11u1'},
    {'release': '11.0', 'prefix': 'zlib1g', 'reference': '1:1.2.11.dfsg-2+deb11u1'},
    {'release': '11.0', 'prefix': 'zlib1g-dbg', 'reference': '1:1.2.11.dfsg-2+deb11u1'},
    {'release': '11.0', 'prefix': 'zlib1g-dev', 'reference': '1:1.2.11.dfsg-2+deb11u1'},
    {'release': '11.0', 'prefix': 'zlib1g-udeb', 'reference': '1:1.2.11.dfsg-2+deb11u1'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lib32z1 / lib32z1-dev / lib64z1 / lib64z1-dev / libn32z1 / etc');
}
