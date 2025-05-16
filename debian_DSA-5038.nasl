#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5038. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156563);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2021-45944", "CVE-2021-45949");

  script_name(english:"Debian DSA-5038-1 : ghostscript - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5038 advisory.

    Multiple security issues were discovered in Ghostscript, the GPL PostScript/PDF interpreter, which could
    result in denial of service and potentially the execution of arbitrary code if malformed document files
    are processed. For the oldstable distribution (buster), these problems have been fixed in version
    9.27~dfsg-2+deb10u5. For the stable distribution (bullseye), these problems have been fixed in version
    9.53.3~dfsg-7+deb11u2. We recommend that you upgrade your ghostscript packages. For the detailed security
    status of ghostscript please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/ghostscript

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ghostscript");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5038");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45944");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45949");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ghostscript");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/ghostscript");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ghostscript packages.

For the stable distribution (bullseye), these problems have been fixed in version 9.53.3~dfsg-7+deb11u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45949");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs9-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'ghostscript', 'reference': '9.27~dfsg-2+deb10u5'},
    {'release': '10.0', 'prefix': 'ghostscript-dbg', 'reference': '9.27~dfsg-2+deb10u5'},
    {'release': '10.0', 'prefix': 'ghostscript-doc', 'reference': '9.27~dfsg-2+deb10u5'},
    {'release': '10.0', 'prefix': 'ghostscript-x', 'reference': '9.27~dfsg-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libgs-dev', 'reference': '9.27~dfsg-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libgs9', 'reference': '9.27~dfsg-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libgs9-common', 'reference': '9.27~dfsg-2+deb10u5'},
    {'release': '11.0', 'prefix': 'ghostscript', 'reference': '9.53.3~dfsg-7+deb11u2'},
    {'release': '11.0', 'prefix': 'ghostscript-dbg', 'reference': '9.53.3~dfsg-7+deb11u2'},
    {'release': '11.0', 'prefix': 'ghostscript-doc', 'reference': '9.53.3~dfsg-7+deb11u2'},
    {'release': '11.0', 'prefix': 'ghostscript-x', 'reference': '9.53.3~dfsg-7+deb11u2'},
    {'release': '11.0', 'prefix': 'libgs-dev', 'reference': '9.53.3~dfsg-7+deb11u2'},
    {'release': '11.0', 'prefix': 'libgs9', 'reference': '9.53.3~dfsg-7+deb11u2'},
    {'release': '11.0', 'prefix': 'libgs9-common', 'reference': '9.53.3~dfsg-7+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ghostscript / ghostscript-dbg / ghostscript-doc / ghostscript-x / etc');
}
