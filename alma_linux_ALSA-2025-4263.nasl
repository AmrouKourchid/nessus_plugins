#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2025:4263.
##

include('compat.inc');

if (description)
{
  script_id(234932);
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
  script_xref(name:"ALSA", value:"2025:4263");
  script_xref(name:"RHSA", value:"2025:4263");

  script_name(english:"AlmaLinux 9 : php:8.1 (ALSA-2025:4263)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2025:4263 advisory.

    * php: Leak partial content of the heap through heap buffer over-read in mysqlnd (CVE-2024-8929)
      * php: Single byte overread with convert.quoted-printable-decode filter (CVE-2024-11233)
      * php: Configuring a proxy in a stream context might allow for CRLF injection in URIs (CVE-2024-11234)
      * php: Header parser of http stream wrapper does not handle folded headers (CVE-2025-1217)
      * php: Stream HTTP wrapper header check might omit basic auth header (CVE-2025-1736)
      * php: Streams HTTP wrapper does not fail for headers with invalid name and no colon (CVE-2025-1734)
      * php: libxml streams use wrong content-type header when requesting a redirected resource
    (CVE-2025-1219)
      * php: Stream HTTP wrapper truncates redirect location to 1024 bytes (CVE-2025-1861)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2025-4263.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:4263");
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
  script_cwe_id(122, 125, 131, 20, 200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pecl-rrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pecl-xdebug3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:8.1');
if ('8.1' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

var appstreams = {
    'php:8.1': [
      {'reference':'apcu-panel-5.1.21-1.module_el9.1.0+15+94ba28e4', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-bcmath-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-bcmath-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-bcmath-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-bcmath-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-cli-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-cli-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-cli-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-cli-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-common-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-common-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-common-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-common-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-dba-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-dba-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-dba-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-dba-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-dbg-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-dbg-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-dbg-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-dbg-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-devel-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-devel-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-devel-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-devel-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-embedded-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-embedded-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-embedded-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-embedded-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-enchant-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-enchant-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-enchant-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-enchant-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-ffi-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-ffi-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-ffi-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-ffi-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-fpm-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-fpm-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-fpm-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-fpm-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-gd-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-gd-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-gd-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-gd-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-gmp-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-gmp-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-gmp-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-gmp-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-intl-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-intl-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-intl-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-intl-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-ldap-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-ldap-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-ldap-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-ldap-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-mbstring-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-mbstring-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-mbstring-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-mbstring-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-mysqlnd-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-mysqlnd-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-mysqlnd-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-mysqlnd-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-odbc-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-odbc-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-odbc-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-odbc-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-opcache-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-opcache-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-opcache-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-opcache-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pdo-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pdo-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pdo-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pdo-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-5.1.21-1.module_el9.1.0+15+94ba28e4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-5.1.21-1.module_el9.1.0+15+94ba28e4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-5.1.21-1.module_el9.1.0+15+94ba28e4', 'cpu':'s390x', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-5.1.21-1.module_el9.1.0+15+94ba28e4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-devel-5.1.21-1.module_el9.1.0+15+94ba28e4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-devel-5.1.21-1.module_el9.1.0+15+94ba28e4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-devel-5.1.21-1.module_el9.1.0+15+94ba28e4', 'cpu':'s390x', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-devel-5.1.21-1.module_el9.1.0+15+94ba28e4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-2.0.3-4.module_el9.1.0+15+94ba28e4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-2.0.3-4.module_el9.1.0+15+94ba28e4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-2.0.3-4.module_el9.1.0+15+94ba28e4', 'cpu':'s390x', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-2.0.3-4.module_el9.1.0+15+94ba28e4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-3.1.4-1.module_el9.1.0+15+94ba28e4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-3.1.4-1.module_el9.1.0+15+94ba28e4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-3.1.4-1.module_el9.1.0+15+94ba28e4', 'cpu':'s390x', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-3.1.4-1.module_el9.1.0+15+94ba28e4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-1.20.1-1.module_el9.1.0+15+94ba28e4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-1.20.1-1.module_el9.1.0+15+94ba28e4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-1.20.1-1.module_el9.1.0+15+94ba28e4', 'cpu':'s390x', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-1.20.1-1.module_el9.1.0+15+94ba28e4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pgsql-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pgsql-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pgsql-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pgsql-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-process-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-process-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-process-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-process-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-snmp-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-snmp-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-snmp-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-snmp-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-soap-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-soap-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-soap-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-soap-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-xml-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-xml-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-xml-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-xml-8.1.32-1.module_el9.5.0+156+9f1cd3fd', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
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
      var exists_check = NULL;
      var cves = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apcu-panel / php / php-bcmath / php-cli / php-common / php-dba / etc');
}
