#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5290-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183134);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2021-21424", "CVE-2021-41270");
  script_xref(name:"USN", value:"5290-1");

  script_name(english:"Ubuntu 18.04 ESM / 20.04 ESM : Symfony vulnerabilities (USN-5290-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 ESM / 20.04 ESM host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5290-1 advisory.

    James Isaac and Mathias Brodala discovered that Symfony incorrectly handled switch users functionality. An
    attacker could possibly use this issue to enumerate users. (CVE-2021-21424)

    It was discovered that Symfony incorrectly handled certain specially crafted CSV files. An attacker could
    possibly use this issue to execute arbitrary code. This issue only affected Ubuntu 20.04 ESM.
    (CVE-2021-41270)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5290-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21424");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-amazon-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-asset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-browser-kit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-class-loader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-css-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-debug-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-dependency-injection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-dom-crawler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-dotenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-event-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-expression-language");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-finder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-form");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-framework-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-google-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-http-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-http-foundation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-inflector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-lock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mailchimp-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mailgun-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-messenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-monolog-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-options-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-phpunit-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-postmark-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-property-access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-property-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-proxy-manager-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-routing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-security-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-security-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-security-csrf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-security-guard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-security-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-sendgrid-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-serializer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-stopwatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-templating");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-translation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-twig-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-twig-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-var-dumper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-var-exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-web-link");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-web-profiler-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-web-server-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-workflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-yaml");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '18.04', 'pkgname': 'php-symfony', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-asset', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-browser-kit', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-cache', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-class-loader', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-config', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-console', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-css-selector', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-debug', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-debug-bundle', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-dependency-injection', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-dom-crawler', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-dotenv', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-event-dispatcher', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-expression-language', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-filesystem', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-finder', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-form', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-framework-bundle', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-http-foundation', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-http-kernel', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-inflector', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-intl', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-ldap', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-lock', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-monolog-bridge', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-options-resolver', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-phpunit-bridge', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-process', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-property-access', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-property-info', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-proxy-manager-bridge', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-routing', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-security', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-security-bundle', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-security-core', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-security-csrf', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-security-guard', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-security-http', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-serializer', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-stopwatch', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-templating', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-translation', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-twig-bridge', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-twig-bundle', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-validator', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-var-dumper', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-web-link', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-web-profiler-bundle', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-web-server-bundle', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-workflow', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-symfony-yaml', 'pkgver': '3.4.6+dfsg-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-amazon-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-asset', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-browser-kit', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-cache', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-config', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-console', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-css-selector', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-debug', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-debug-bundle', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-dependency-injection', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-dom-crawler', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-dotenv', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-event-dispatcher', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-expression-language', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-filesystem', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-finder', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-form', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-framework-bundle', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-google-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-http-client', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-http-foundation', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-http-kernel', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-inflector', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-intl', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-ldap', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-lock', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-mailchimp-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-mailgun-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-messenger', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-mime', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-monolog-bridge', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-options-resolver', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-phpunit-bridge', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-postmark-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-process', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-property-access', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-property-info', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-proxy-manager-bridge', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-routing', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-security', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-security-bundle', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-security-core', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-security-csrf', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-security-guard', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-security-http', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-sendgrid-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-serializer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-stopwatch', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-templating', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-translation', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-twig-bridge', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-twig-bundle', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-validator', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-var-dumper', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-var-exporter', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-web-link', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-web-profiler-bundle', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-web-server-bundle', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-workflow', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-yaml', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm1', 'ubuntu_pro': TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php-symfony / php-symfony-amazon-mailer / php-symfony-asset / etc');
}
