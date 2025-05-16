#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-2417.
##

include('compat.inc');

if (description)
{
  script_id(175729);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2022-31628",
    "CVE-2022-31629",
    "CVE-2022-31630",
    "CVE-2022-31631",
    "CVE-2022-37454"
  );
  script_xref(name:"IAVA", value:"2022-A-0455-S");
  script_xref(name:"IAVA", value:"2022-A-0515-S");
  script_xref(name:"IAVA", value:"2023-A-0016-S");
  script_xref(name:"IAVA", value:"2022-A-0397-S");

  script_name(english:"Oracle Linux 9 : 8.1 (ELSA-2023-2417)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-2417 advisory.

    php-pecl-apcu
    [5.1.21-1]
    - update to 5.1.21 for PHP 8.1 #2070040

    php-pecl-rrd
    [2.0.3-4]
    - build for PHP 8.1 #2070040

    php-pecl-xdebug3
    [3.1.4-1]
    - update to 3.1.4 for PHP 8.1 #2070040

    php-pecl-zip
    [1.20.1-1]
    - update to 1.20.1 for PHP 8.1 #2070040

    php
    [8.1.14-1]
    - rebase to 8.1.14

    [8.1.8-1]
    - update to 8.1.8 #2070040

    [8.1.7-2]
    - clean unneeded dependency on useradd command

    [8.1.7-1]
    - update to 8.1.7 #2070040

    [8.1.6-2]
    - add upstream patch to initialize pcre before mbstring
    - add upstream patch to use more sha256 in openssl tests

    [8.1.6-1]
    - update to 8.1.6 #2070040

    [8.0.13-1]
    - rebase to 8.0.13 #2032429
    - refresh configuration files from upstream

    [8.0.12-1]
    - rebase to 8.0.12 #2017111 #1981423
    - build using system libxcrypt #2015903

    [8.0.10-1]
    - rebase to 8.0.10 #1992513
    - compatibility with OpenSSL 3.0 #1992492
    - snmp:  add sha256 / sha512 security protocol #1936635
    - phar: implement openssl_256 and openssl_512 for phar signatures
    - phar: use sha256 signature by default

    [8.0.6-9]
    - Rebuilt for libffi 3.4.2 SONAME transition.
      Related: rhbz#1891914

    [8.0.6-8]
    - Rebuilt for IMA sigs, glibc 2.34, aarch64 flags
      Related: rhbz#1991688

    [8.0.6-7]
    - Rebuild to pick up new build flags from redhat-rpm-config (#1984652)

    [8.0.6-6]
    - Rebuilt for RHEL 9 BETA for openssl 3.0
      Related: rhbz#1971065

    [8.0.6-5]
    - fix build with net-snmp without DES #1953492

    [8.0.6-4]
    - fix build with openssl 3.0 #1953492

    [8.0.6-3]
    - get rid of inet_addr and gethostbyaddr calls

    [8.0.6-2]
    - get rid of inet_ntoa and inet_aton calls

    [8.0.6-1]
    - Update to 8.0.6 - http://www.php.net/releases/8_0_6.php

    [8.0.5-1]
    - Update to 8.0.5 - http://www.php.net/releases/8_0_5.php

    [8.0.5~RC1-1]
    - update to 8.0.5RC1

    [8.0.4~RC1-2]
    - make libdb usage conditional
      default: on for Fedora, off for RHEL

    [8.0.4~RC1-1]
    - update to 8.0.4RC1

    [8.0.3-2]
    - clean conditions

    [8.0.3-1]
    - Update to 8.0.3 - http://www.php.net/releases/8_0_3.php
    - see https://fedoraproject.org/wiki/Changes/php80
    - drop xmlrpc extension
    - drop json subpackage, extension always there
    - enchant: use libenchant-2 instead of libenchant

    [7.4.16-1]
    - Update to 7.4.16 - http://www.php.net/releases/7_4_16.php

    [7.4.15-3]
    - drop php-imap, fix #1929640

    [7.4.15-2]
    - rebuild for libpq ABI fix rhbz#1908268

    [7.4.15-1]
    - Update to 7.4.15 - http://www.php.net/releases/7_4_15.php
    - add upstream patch for https://bugs.php.net/80682
      fix opcache doesn't honour pcre.jit option

    [7.4.15~RC2-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

    [7.4.15~RC2-1]
    - update to 7.4.15RC2

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-2417.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37454");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-rrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-xdebug3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xml");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:8.1');
if ('8.1' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

var appstreams = {
    'php:8.1': [
      {'reference':'apcu-panel-5.1.21-1.module+el9.1.0+20776+c1b960c0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ffi-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-5.1.21-1.module+el9.1.0+20776+c1b960c0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.21-1.module+el9.1.0+20776+c1b960c0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-rrd-2.0.3-4.module+el9.1.0+20776+c1b960c0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-xdebug3-3.1.4-1.module+el9.1.0+20776+c1b960c0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.20.1-1.module+el9.1.0+20776+c1b960c0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ffi-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-5.1.21-1.module+el9.1.0+20776+c1b960c0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.21-1.module+el9.1.0+20776+c1b960c0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-rrd-2.0.3-4.module+el9.1.0+20776+c1b960c0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-xdebug3-3.1.4-1.module+el9.1.0+20776+c1b960c0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.20.1-1.module+el9.1.0+20776+c1b960c0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-8.1.14-1.module+el9.2.0+20960+2088691d', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:8.1');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apcu-panel / php / php-bcmath / etc');
}
