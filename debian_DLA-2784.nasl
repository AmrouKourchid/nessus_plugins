#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2784. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154020);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2020-21913");

  script_name(english:"Debian DLA-2784-1 : icu - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2784
advisory.

    It was discovered that there was a potential use-after-free vulnerability in icu, a library which provides
    Unicode and locale functionality. CVE-2020-21913 International Components for Unicode (ICU-20850) v66.1
    was discovered to contain a use after free bug in the pkg_createWithAssemblyCode function in the file
    tools/pkgdata/pkgdata.cpp. For Debian 9 Stretch, these problems have been fixed in version 57.1-6+deb9u5.
    We recommend that you upgrade your icu packages. Further information about Debian LTS security advisories,
    how to apply these updates to your system and frequently asked questions can be found at:
    https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2784");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21913");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/icu");
  script_set_attribute(attribute:"solution", value:
"Upgrade the icu packages.

For Debian 9 Stretch, these problems have been fixed in version 57.1-6+deb9u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-21913");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icu-devtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icu-devtools-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icu-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libicu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libicu57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libicu57-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (! preg(pattern:"^(9)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'icu-devtools', 'reference': '57.1-6+deb9u5'},
    {'release': '9.0', 'prefix': 'icu-devtools-dbg', 'reference': '57.1-6+deb9u5'},
    {'release': '9.0', 'prefix': 'icu-doc', 'reference': '57.1-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libicu-dev', 'reference': '57.1-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libicu57', 'reference': '57.1-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libicu57-dbg', 'reference': '57.1-6+deb9u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'icu-devtools / icu-devtools-dbg / icu-doc / libicu-dev / libicu57 / etc');
}
