#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5567. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(186306);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2023-3576", "CVE-2023-40745", "CVE-2023-41175");

  script_name(english:"Debian DSA-5567-1 : tiff - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5567 advisory.

  - A memory leak flaw was found in Libtiff's tiffcrop utility. This issue occurs when tiffcrop operates on a
    TIFF image file, allowing an attacker to pass a crafted TIFF image file to tiffcrop utility, which causes
    this memory leak issue, resulting an application crash, eventually leading to a denial of service.
    (CVE-2023-3576)

  - LibTIFF is vulnerable to an integer overflow. This flaw allows remote attackers to cause a denial of
    service (application crash) or possibly execute an arbitrary code via a crafted tiff image, which triggers
    a heap-based buffer overflow. (CVE-2023-40745)

  - A vulnerability was found in libtiff due to multiple potential integer overflows in raw2tiff.c. This flaw
    allows remote attackers to cause a denial of service or possibly execute an arbitrary code via a crafted
    tiff image, which triggers a heap-based buffer overflow. (CVE-2023-41175)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/tiff");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5567");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3576");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40745");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-41175");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/tiff");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/tiff");
  script_set_attribute(attribute:"solution", value:
"Upgrade the tiff packages.

For the stable distribution (bookworm), these problems have been fixed in version 4.5.0-6+deb12u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41175");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx6");
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
    {'release': '11.0', 'prefix': 'libtiff-dev', 'reference': '4.2.0-1+deb11u5'},
    {'release': '11.0', 'prefix': 'libtiff-doc', 'reference': '4.2.0-1+deb11u5'},
    {'release': '11.0', 'prefix': 'libtiff-opengl', 'reference': '4.2.0-1+deb11u5'},
    {'release': '11.0', 'prefix': 'libtiff-tools', 'reference': '4.2.0-1+deb11u5'},
    {'release': '11.0', 'prefix': 'libtiff5', 'reference': '4.2.0-1+deb11u5'},
    {'release': '11.0', 'prefix': 'libtiff5-dev', 'reference': '4.2.0-1+deb11u5'},
    {'release': '11.0', 'prefix': 'libtiffxx5', 'reference': '4.2.0-1+deb11u5'},
    {'release': '12.0', 'prefix': 'libtiff-dev', 'reference': '4.5.0-6+deb12u1'},
    {'release': '12.0', 'prefix': 'libtiff-doc', 'reference': '4.5.0-6+deb12u1'},
    {'release': '12.0', 'prefix': 'libtiff-opengl', 'reference': '4.5.0-6+deb12u1'},
    {'release': '12.0', 'prefix': 'libtiff-tools', 'reference': '4.5.0-6+deb12u1'},
    {'release': '12.0', 'prefix': 'libtiff5-dev', 'reference': '4.5.0-6+deb12u1'},
    {'release': '12.0', 'prefix': 'libtiff6', 'reference': '4.5.0-6+deb12u1'},
    {'release': '12.0', 'prefix': 'libtiffxx6', 'reference': '4.5.0-6+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtiff-dev / libtiff-doc / libtiff-opengl / libtiff-tools / libtiff5 / etc');
}
