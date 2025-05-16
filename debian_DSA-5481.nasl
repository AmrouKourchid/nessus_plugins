#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5481. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(180015);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2023-39534",
    "CVE-2023-39945",
    "CVE-2023-39946",
    "CVE-2023-39947",
    "CVE-2023-39948",
    "CVE-2023-39949"
  );

  script_name(english:"Debian DSA-5481-1 : fastdds - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5481 advisory.

    Multipe security issues were discovered in Fast DDS, a C++ implementation of the DDS (Data Distribution
    Service), which might result in denial of service or potentially the execution of arbitrary code when
    processing malformed RTPS packets. For the oldstable distribution (bullseye), these problems have been
    fixed in version 2.1.0+ds-9+deb11u1. For the stable distribution (bookworm), these problems have been
    fixed in version 2.9.1+ds-1+deb12u1. We recommend that you upgrade your fastdds packages. For the detailed
    security status of fastdds please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/fastdds

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/fastdds");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5481");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39534");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39945");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39946");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39947");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39948");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39949");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/fastdds");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/fastdds");
  script_set_attribute(attribute:"solution", value:
"Upgrade the fastdds packages.

For the stable distribution (bookworm), these problems have been fixed in version 2.9.1+ds-1+deb12u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39949");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fastdds-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfastrtps-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfastrtps-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfastrtps2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfastrtps2.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'fastdds-tools', 'reference': '2.1.0+ds-9+deb11u1'},
    {'release': '11.0', 'prefix': 'libfastrtps-dev', 'reference': '2.1.0+ds-9+deb11u1'},
    {'release': '11.0', 'prefix': 'libfastrtps-doc', 'reference': '2.1.0+ds-9+deb11u1'},
    {'release': '11.0', 'prefix': 'libfastrtps2', 'reference': '2.1.0+ds-9+deb11u1'},
    {'release': '12.0', 'prefix': 'fastdds-tools', 'reference': '2.9.1+ds-1+deb12u1'},
    {'release': '12.0', 'prefix': 'libfastrtps-dev', 'reference': '2.9.1+ds-1+deb12u1'},
    {'release': '12.0', 'prefix': 'libfastrtps-doc', 'reference': '2.9.1+ds-1+deb12u1'},
    {'release': '12.0', 'prefix': 'libfastrtps2.9', 'reference': '2.9.1+ds-1+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fastdds-tools / libfastrtps-dev / libfastrtps-doc / libfastrtps2 / etc');
}
