#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5051. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156948);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2021-45417");

  script_name(english:"Debian DSA-5051-1 : aide - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5051
advisory.

    David Bouman discovered a heap-based buffer overflow vulnerability in the base64 functions of aide, an
    advanced intrusion detection system, which can be triggered via large extended file attributes or ACLs.
    This may result in denial of service or privilege escalation. For the oldstable distribution (buster),
    this problem has been fixed in version 0.16.1-1+deb10u1. For the stable distribution (bullseye), this
    problem has been fixed in version 0.17.3-4+deb11u1. We recommend that you upgrade your aide packages. For
    the detailed security status of aide please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/aide

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/aide");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5051");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45417");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/aide");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/aide");
  script_set_attribute(attribute:"solution", value:
"Upgrade the aide packages.

For the stable distribution (bullseye), this problem has been fixed in version 0.17.3-4+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45417");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:aide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:aide-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:aide-dynamic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:aide-xen");
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
    {'release': '10.0', 'prefix': 'aide', 'reference': '0.16.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'aide-common', 'reference': '0.16.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'aide-dynamic', 'reference': '0.16.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'aide-xen', 'reference': '0.16.1-1+deb10u1'},
    {'release': '11.0', 'prefix': 'aide', 'reference': '0.17.3-4+deb11u1'},
    {'release': '11.0', 'prefix': 'aide-common', 'reference': '0.17.3-4+deb11u1'},
    {'release': '11.0', 'prefix': 'aide-dynamic', 'reference': '0.17.3-4+deb11u1'},
    {'release': '11.0', 'prefix': 'aide-xen', 'reference': '0.17.3-4+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aide / aide-common / aide-dynamic / aide-xen');
}
