#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5032. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156331);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2019-15142",
    "CVE-2019-15143",
    "CVE-2019-15144",
    "CVE-2019-15145",
    "CVE-2019-18804",
    "CVE-2021-3500",
    "CVE-2021-3630",
    "CVE-2021-32490",
    "CVE-2021-32491",
    "CVE-2021-32492",
    "CVE-2021-32493"
  );

  script_name(english:"Debian DSA-5032-1 : djvulibre - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5032 advisory.

    Several vulnerabilities were discovered in djvulibre, a library and set of tools to handle documents in
    the DjVu format. An attacker could crash document viewers and possibly execute arbitrary code through
    crafted DjVu files. For the oldstable distribution (buster), these problems have been fixed in version
    3.5.27.1-10+deb10u1. For the stable distribution (bullseye), these problems have been fixed in version
    3.5.28-2. We recommend that you upgrade your djvulibre packages. For the detailed security status of
    djvulibre please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/djvulibre

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=945114");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/djvulibre");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-5032");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-15142");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-15143");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-15144");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-15145");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-18804");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32490");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32491");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32492");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32493");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3500");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3630");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/djvulibre");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/djvulibre");
  script_set_attribute(attribute:"solution", value:
"Upgrade the djvulibre packages.

For the stable distribution (bullseye), these problems have been fixed in version 3.5.28-2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3500");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:djview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:djview3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:djvulibre-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:djvulibre-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:djvuserve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdjvulibre-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdjvulibre-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdjvulibre21");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'djview', 'reference': '3.5.27.1-10+deb10u1'},
    {'release': '10.0', 'prefix': 'djview3', 'reference': '3.5.27.1-10+deb10u1'},
    {'release': '10.0', 'prefix': 'djvulibre-bin', 'reference': '3.5.27.1-10+deb10u1'},
    {'release': '10.0', 'prefix': 'djvulibre-desktop', 'reference': '3.5.27.1-10+deb10u1'},
    {'release': '10.0', 'prefix': 'djvuserve', 'reference': '3.5.27.1-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libdjvulibre-dev', 'reference': '3.5.27.1-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libdjvulibre-text', 'reference': '3.5.27.1-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libdjvulibre21', 'reference': '3.5.27.1-10+deb10u1'},
    {'release': '11.0', 'prefix': 'djview', 'reference': '3.5.28-2'},
    {'release': '11.0', 'prefix': 'djview3', 'reference': '3.5.28-2'},
    {'release': '11.0', 'prefix': 'djvulibre-bin', 'reference': '3.5.28-2'},
    {'release': '11.0', 'prefix': 'djvulibre-desktop', 'reference': '3.5.28-2'},
    {'release': '11.0', 'prefix': 'djvuserve', 'reference': '3.5.28-2'},
    {'release': '11.0', 'prefix': 'libdjvulibre-dev', 'reference': '3.5.28-2'},
    {'release': '11.0', 'prefix': 'libdjvulibre-text', 'reference': '3.5.28-2'},
    {'release': '11.0', 'prefix': 'libdjvulibre21', 'reference': '3.5.28-2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'djview / djview3 / djvulibre-bin / djvulibre-desktop / djvuserve / etc');
}
