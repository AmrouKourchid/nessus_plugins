#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2025-4263.
##

include('compat.inc');

if (description)
{
  script_id(234955);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id(
    "CVE-2024-8929",
    "CVE-2024-11233",
    "CVE-2024-11234",
    "CVE-2025-1217",
    "CVE-2025-1219",
    "CVE-2025-1734",
    "CVE-2025-1736",
    "CVE-2025-1861"
  );
  script_xref(name:"IAVA", value:"2024-A-0763-S");
  script_xref(name:"IAVA", value:"2025-A-0183");

  script_name(english:"Oracle Linux 9 : php:8.1 (ELSA-2025-4263)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2025-4263 advisory.

    php
    [8.1.32-1]
    - rebase to 8.1.32

    php-pecl-apcu
    php-pecl-rrd
    php-pecl-xdebug3
    php-pecl-zip:

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2025-4263.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11233");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-1861");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:1:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:2:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:3:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:4:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:5:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:5:appstream_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream_developer");
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

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'php-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ffi-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-5.1.21-1.module+el9.1.0+20776+c1b960c0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.21-1.module+el9.1.0+20776+c1b960c0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-rrd-2.0.3-4.module+el9.1.0+20776+c1b960c0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-xdebug3-3.1.4-1.module+el9.1.0+20776+c1b960c0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.20.1-1.module+el9.1.0+20776+c1b960c0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ffi-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-5.1.21-1.module+el9.1.0+20776+c1b960c0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.21-1.module+el9.1.0+20776+c1b960c0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-rrd-2.0.3-4.module+el9.1.0+20776+c1b960c0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-xdebug3-3.1.4-1.module+el9.1.0+20776+c1b960c0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.20.1-1.module+el9.1.0+20776+c1b960c0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-8.1.32-1.module+el9.5.0+90557+5e9037e7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
