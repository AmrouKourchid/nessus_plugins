#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:4263. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234912);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

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
  script_xref(name:"RHSA", value:"2025:4263");

  script_name(english:"RHEL 9 : php:8.1 (RHSA-2025:4263)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for php:8.1.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2025:4263 advisory.

    PHP is an HTML-embedded scripting language commonly used with the Apache HTTP Server.

    Security Fix(es):

    * php: Leak partial content of the heap through heap buffer over-read in mysqlnd (CVE-2024-8929)

    * php: Single byte overread with convert.quoted-printable-decode filter (CVE-2024-11233)

    * php: Configuring a proxy in a stream context might allow for CRLF injection in URIs (CVE-2024-11234)

    * php: Header parser of http stream wrapper does not handle folded headers (CVE-2025-1217)

    * php: Stream HTTP wrapper header check might omit basic auth header (CVE-2025-1736)

    * php: Streams HTTP wrapper does not fail for headers with invalid name and no colon (CVE-2025-1734)

    * php: libxml streams use wrong content-type header when requesting a redirected resource (CVE-2025-1219)

    * php: Stream HTTP wrapper truncates redirect location to 1024 bytes (CVE-2025-1861)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2328521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2328523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2355917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356046");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_4263.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1e8c4a1");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:4263");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL php:8.1 package based on the guidance in RHSA-2025:4263.");
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
  script_cwe_id(20, 122, 131, 200);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-rrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-xdebug3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xml");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'php:8.1': [
    {
      'repo_relative_urls': [
        'content/dist/rhel9/9.1/aarch64/appstream/debug',
        'content/dist/rhel9/9.1/aarch64/appstream/os',
        'content/dist/rhel9/9.1/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.1/ppc64le/appstream/debug',
        'content/dist/rhel9/9.1/ppc64le/appstream/os',
        'content/dist/rhel9/9.1/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.1/s390x/appstream/debug',
        'content/dist/rhel9/9.1/s390x/appstream/os',
        'content/dist/rhel9/9.1/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.1/x86_64/appstream/debug',
        'content/dist/rhel9/9.1/x86_64/appstream/os',
        'content/dist/rhel9/9.1/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.2/aarch64/appstream/debug',
        'content/dist/rhel9/9.2/aarch64/appstream/os',
        'content/dist/rhel9/9.2/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.2/ppc64le/appstream/debug',
        'content/dist/rhel9/9.2/ppc64le/appstream/os',
        'content/dist/rhel9/9.2/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.2/s390x/appstream/debug',
        'content/dist/rhel9/9.2/s390x/appstream/os',
        'content/dist/rhel9/9.2/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.2/x86_64/appstream/debug',
        'content/dist/rhel9/9.2/x86_64/appstream/os',
        'content/dist/rhel9/9.2/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.3/aarch64/appstream/debug',
        'content/dist/rhel9/9.3/aarch64/appstream/os',
        'content/dist/rhel9/9.3/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.3/ppc64le/appstream/debug',
        'content/dist/rhel9/9.3/ppc64le/appstream/os',
        'content/dist/rhel9/9.3/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.3/s390x/appstream/debug',
        'content/dist/rhel9/9.3/s390x/appstream/os',
        'content/dist/rhel9/9.3/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.3/x86_64/appstream/debug',
        'content/dist/rhel9/9.3/x86_64/appstream/os',
        'content/dist/rhel9/9.3/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.4/aarch64/appstream/debug',
        'content/dist/rhel9/9.4/aarch64/appstream/os',
        'content/dist/rhel9/9.4/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.4/ppc64le/appstream/debug',
        'content/dist/rhel9/9.4/ppc64le/appstream/os',
        'content/dist/rhel9/9.4/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.4/s390x/appstream/debug',
        'content/dist/rhel9/9.4/s390x/appstream/os',
        'content/dist/rhel9/9.4/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.4/x86_64/appstream/debug',
        'content/dist/rhel9/9.4/x86_64/appstream/os',
        'content/dist/rhel9/9.4/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.5/aarch64/appstream/debug',
        'content/dist/rhel9/9.5/aarch64/appstream/os',
        'content/dist/rhel9/9.5/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.5/ppc64le/appstream/debug',
        'content/dist/rhel9/9.5/ppc64le/appstream/os',
        'content/dist/rhel9/9.5/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.5/s390x/appstream/debug',
        'content/dist/rhel9/9.5/s390x/appstream/os',
        'content/dist/rhel9/9.5/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.5/x86_64/appstream/debug',
        'content/dist/rhel9/9.5/x86_64/appstream/os',
        'content/dist/rhel9/9.5/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.6/aarch64/appstream/debug',
        'content/dist/rhel9/9.6/aarch64/appstream/os',
        'content/dist/rhel9/9.6/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.6/ppc64le/appstream/debug',
        'content/dist/rhel9/9.6/ppc64le/appstream/os',
        'content/dist/rhel9/9.6/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.6/s390x/appstream/debug',
        'content/dist/rhel9/9.6/s390x/appstream/os',
        'content/dist/rhel9/9.6/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.6/x86_64/appstream/debug',
        'content/dist/rhel9/9.6/x86_64/appstream/os',
        'content/dist/rhel9/9.6/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.7/aarch64/appstream/debug',
        'content/dist/rhel9/9.7/aarch64/appstream/os',
        'content/dist/rhel9/9.7/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.7/ppc64le/appstream/debug',
        'content/dist/rhel9/9.7/ppc64le/appstream/os',
        'content/dist/rhel9/9.7/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.7/s390x/appstream/debug',
        'content/dist/rhel9/9.7/s390x/appstream/os',
        'content/dist/rhel9/9.7/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.7/x86_64/appstream/debug',
        'content/dist/rhel9/9.7/x86_64/appstream/os',
        'content/dist/rhel9/9.7/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9/aarch64/appstream/debug',
        'content/dist/rhel9/9/aarch64/appstream/os',
        'content/dist/rhel9/9/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9/ppc64le/appstream/debug',
        'content/dist/rhel9/9/ppc64le/appstream/os',
        'content/dist/rhel9/9/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9/s390x/appstream/debug',
        'content/dist/rhel9/9/s390x/appstream/os',
        'content/dist/rhel9/9/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9/x86_64/appstream/debug',
        'content/dist/rhel9/9/x86_64/appstream/os',
        'content/dist/rhel9/9/x86_64/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi9/9/aarch64/appstream/debug',
        'content/public/ubi/dist/ubi9/9/aarch64/appstream/os',
        'content/public/ubi/dist/ubi9/9/aarch64/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi9/9/ppc64le/appstream/debug',
        'content/public/ubi/dist/ubi9/9/ppc64le/appstream/os',
        'content/public/ubi/dist/ubi9/9/ppc64le/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi9/9/s390x/appstream/debug',
        'content/public/ubi/dist/ubi9/9/s390x/appstream/os',
        'content/public/ubi/dist/ubi9/9/s390x/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi9/9/x86_64/appstream/debug',
        'content/public/ubi/dist/ubi9/9/x86_64/appstream/os',
        'content/public/ubi/dist/ubi9/9/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'apcu-panel-5.1.21-1.module+el9.1.0.z+15477+cb86791d', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-bcmath-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-cli-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-common-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dba-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dbg-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-devel-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-embedded-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-enchant-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-ffi-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-fpm-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gd-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gmp-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-intl-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-ldap-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mbstring-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mysqlnd-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-odbc-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-opcache-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pdo-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-apcu-5.1.21-1.module+el9.1.0.z+15477+cb86791d', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-apcu-devel-5.1.21-1.module+el9.1.0.z+15477+cb86791d', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-rrd-2.0.3-4.module+el9.1.0.z+15477+cb86791d', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-xdebug3-3.1.4-1.module+el9.1.0.z+15477+cb86791d', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-zip-1.20.1-1.module+el9.1.0.z+15477+cb86791d', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pgsql-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-process-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-snmp-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-soap-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xml-8.1.32-1.module+el9.5.0+23047+aadb97d2', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:8.1');
if ('8.1' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

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
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      foreach var package_array ( module_array['pkgs'] ) {
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
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:8.1');

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apcu-panel / php / php-bcmath / php-cli / php-common / php-dba / etc');
}
