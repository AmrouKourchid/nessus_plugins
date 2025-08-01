#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5107. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159202);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/03");

  script_cve_id("CVE-2022-23614");

  script_name(english:"Debian DSA-5107-1 : php-twig - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5107
advisory.

  - Twig is an open source template language for PHP. When in a sandbox mode, the `arrow` parameter of the
    `sort` filter must be a closure to avoid attackers being able to run arbitrary PHP functions. In affected
    versions this constraint was not properly enforced and could lead to code injection of arbitrary PHP code.
    Patched versions now disallow calling non Closure in the `sort` filter as is the case for some other
    filters. Users are advised to upgrade. (CVE-2022-23614)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php-twig");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5107");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23614");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/php-twig");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php-twig packages.

For the stable distribution (bullseye), this problem has been fixed in version 2.14.3-1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23614");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-twig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-twig-cssinliner-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-twig-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-twig-extra-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-twig-html-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-twig-inky-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-twig-intl-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-twig-markdown-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'php-twig', 'reference': '2.14.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php-twig-cssinliner-extra', 'reference': '2.14.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php-twig-doc', 'reference': '2.14.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php-twig-extra-bundle', 'reference': '2.14.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php-twig-html-extra', 'reference': '2.14.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php-twig-inky-extra', 'reference': '2.14.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php-twig-intl-extra', 'reference': '2.14.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php-twig-markdown-extra', 'reference': '2.14.3-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php-twig / php-twig-cssinliner-extra / php-twig-doc / etc');
}
