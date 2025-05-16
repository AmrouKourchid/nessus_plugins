#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3664. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(186245);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2023-46734");

  script_name(english:"Debian dla-3664 : php-symfony - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3664
advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3664-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    November 24, 2023                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : symfony
    Version        : 3.4.22+dfsg-2+deb10u3
    CVE ID         : CVE-2023-46734
    Debian Bug     : 1055774

    Pierre Rudloff discovered a potential XSS vulnerability in Symfony, a PHP
    framework. Some Twig filters in CodeExtension use `is_safe=html` but do not
    actually ensure their input is safe. Symfony now escapes the output of the
    affected filters.

    For Debian 10 buster, this problem has been fixed in version
    3.4.22+dfsg-2+deb10u3.

    We recommend that you upgrade your symfony packages.

    For the detailed security status of symfony please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/symfony

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/symfony");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46734");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/symfony");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php-symfony packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46734");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-asset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-browser-kit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-class-loader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-css-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-debug-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-dependency-injection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-doctrine-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-dom-crawler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-dotenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-event-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-expression-language");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-finder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-form");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-framework-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-http-foundation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-http-kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-inflector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-lock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-monolog-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-options-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-phpunit-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-property-access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-property-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-proxy-manager-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-routing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security-csrf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security-guard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-serializer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-stopwatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-templating");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-translation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-twig-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-twig-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-var-dumper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-web-link");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-web-profiler-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-web-server-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-workflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-yaml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'php-symfony', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-asset', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-browser-kit', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-cache', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-class-loader', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-config', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-console', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-css-selector', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-debug', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-debug-bundle', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-dependency-injection', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-doctrine-bridge', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-dom-crawler', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-dotenv', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-event-dispatcher', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-expression-language', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-filesystem', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-finder', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-form', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-framework-bundle', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-http-foundation', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-http-kernel', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-inflector', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-intl', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-ldap', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-lock', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-monolog-bridge', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-options-resolver', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-phpunit-bridge', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-process', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-property-access', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-property-info', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-proxy-manager-bridge', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-routing', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-security', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-security-bundle', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-security-core', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-security-csrf', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-security-guard', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-security-http', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-serializer', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-stopwatch', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-templating', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-translation', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-twig-bridge', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-twig-bundle', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-validator', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-var-dumper', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-web-link', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-web-profiler-bundle', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-web-server-bundle', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-workflow', 'reference': '3.4.22+dfsg-2+deb10u3'},
    {'release': '10.0', 'prefix': 'php-symfony-yaml', 'reference': '3.4.22+dfsg-2+deb10u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php-symfony / php-symfony-asset / php-symfony-browser-kit / etc');
}
