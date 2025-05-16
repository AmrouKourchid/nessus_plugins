#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1824. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78986);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2013-6420");
  script_xref(name:"RHSA", value:"2013:1824");

  script_name(english:"RHEL 5 / 6 : php (RHSA-2013:1824)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for php.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 / 6 host has packages installed that are affected by a vulnerability as referenced
in the RHSA-2013:1824 advisory.

    PHP is an HTML-embedded scripting language commonly used with the Apache
    HTTP Server.

    A memory corruption flaw was found in the way the openssl_x509_parse()
    function of the PHP openssl extension parsed X.509 certificates. A remote
    attacker could use this flaw to provide a malicious self-signed certificate
    or a certificate signed by a trusted authority to a PHP application using
    the aforementioned function, causing the application to crash or, possibly,
    allow the attacker to execute arbitrary code with the privileges of the
    user running the PHP interpreter. (CVE-2013-6420)

    Red Hat would like to thank the PHP project for reporting this issue.
    Upstream acknowledges Stefan Esser as the original reporter of this issue.

    All php users are advised to upgrade to these updated packages, which
    contain a backported patch to correct this issue. After installing the
    updated packages, the httpd daemon must be restarted for the update to
    take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2013/rhsa-2013_1824.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95ade269");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:1824");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1036830");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL php package based on the guidance in RHSA-2013:1824.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-6420");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-zts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:6.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:6.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_mission_critical:5.3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['5.6','5.9','6.2','6.3','6.4'])) audit(AUDIT_OS_NOT, 'Red Hat 5.6 / 5.9 / 6.2 / 6.3 / 6.4', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/5/5.6/i386/debug',
      'content/aus/rhel/server/5/5.6/i386/os',
      'content/aus/rhel/server/5/5.6/i386/source/SRPMS',
      'content/aus/rhel/server/5/5.6/x86_64/debug',
      'content/aus/rhel/server/5/5.6/x86_64/os',
      'content/aus/rhel/server/5/5.6/x86_64/source/SRPMS',
      'content/eus/rhel/power/5/5.6/ppc/os',
      'content/eus/rhel/power/5/5.6/ppc/source/SRPMS',
      'content/eus/rhel/server/5/5.6/i386/os',
      'content/eus/rhel/server/5/5.6/i386/source/SRPMS',
      'content/eus/rhel/server/5/5.6/x86_64/os',
      'content/eus/rhel/server/5/5.6/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/5/5.6/s390x/os',
      'content/eus/rhel/system-z/5/5.6/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'php-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ncurses-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ncurses-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ncurses-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ncurses-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.1.6-27.el5_6.6', 'sp':'6', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/5/5.9/i386/debug',
      'content/aus/rhel/server/5/5.9/i386/os',
      'content/aus/rhel/server/5/5.9/i386/source/SRPMS',
      'content/aus/rhel/server/5/5.9/x86_64/debug',
      'content/aus/rhel/server/5/5.9/x86_64/os',
      'content/aus/rhel/server/5/5.9/x86_64/source/SRPMS',
      'content/eus/rhel/power/5/5.9/ppc/debug',
      'content/eus/rhel/power/5/5.9/ppc/os',
      'content/eus/rhel/power/5/5.9/ppc/source/SRPMS',
      'content/eus/rhel/server/5/5.9/i386/debug',
      'content/eus/rhel/server/5/5.9/i386/os',
      'content/eus/rhel/server/5/5.9/i386/source/SRPMS',
      'content/eus/rhel/server/5/5.9/x86_64/debug',
      'content/eus/rhel/server/5/5.9/x86_64/os',
      'content/eus/rhel/server/5/5.9/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/5/5.9/s390x/debug',
      'content/eus/rhel/system-z/5/5.9/s390x/os',
      'content/eus/rhel/system-z/5/5.9/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'php-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ncurses-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ncurses-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ncurses-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ncurses-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.1.6-40.el5_9.1', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.2/x86_64/debug',
      'content/aus/rhel/server/6/6.2/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.2/x86_64/optional/os',
      'content/aus/rhel/server/6/6.2/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.2/x86_64/os',
      'content/aus/rhel/server/6/6.2/x86_64/source/SRPMS',
      'content/eus/rhel/computenode/6/6.2/x86_64/debug',
      'content/eus/rhel/computenode/6/6.2/x86_64/optional/debug',
      'content/eus/rhel/computenode/6/6.2/x86_64/optional/os',
      'content/eus/rhel/computenode/6/6.2/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/6/6.2/x86_64/os',
      'content/eus/rhel/computenode/6/6.2/x86_64/sfs/debug',
      'content/eus/rhel/computenode/6/6.2/x86_64/sfs/os',
      'content/eus/rhel/computenode/6/6.2/x86_64/sfs/source/SRPMS',
      'content/eus/rhel/computenode/6/6.2/x86_64/source/SRPMS',
      'content/eus/rhel/power/6/6.2/ppc64/debug',
      'content/eus/rhel/power/6/6.2/ppc64/optional/debug',
      'content/eus/rhel/power/6/6.2/ppc64/optional/os',
      'content/eus/rhel/power/6/6.2/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/6/6.2/ppc64/os',
      'content/eus/rhel/power/6/6.2/ppc64/source/SRPMS',
      'content/eus/rhel/server/6/6.2/i386/debug',
      'content/eus/rhel/server/6/6.2/i386/highavailability/debug',
      'content/eus/rhel/server/6/6.2/i386/highavailability/os',
      'content/eus/rhel/server/6/6.2/i386/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.2/i386/loadbalancer/debug',
      'content/eus/rhel/server/6/6.2/i386/loadbalancer/os',
      'content/eus/rhel/server/6/6.2/i386/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.2/i386/optional/debug',
      'content/eus/rhel/server/6/6.2/i386/optional/os',
      'content/eus/rhel/server/6/6.2/i386/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.2/i386/os',
      'content/eus/rhel/server/6/6.2/i386/resilientstorage/debug',
      'content/eus/rhel/server/6/6.2/i386/resilientstorage/os',
      'content/eus/rhel/server/6/6.2/i386/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.2/i386/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/debug',
      'content/eus/rhel/server/6/6.2/x86_64/highavailability/debug',
      'content/eus/rhel/server/6/6.2/x86_64/highavailability/os',
      'content/eus/rhel/server/6/6.2/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/loadbalancer/debug',
      'content/eus/rhel/server/6/6.2/x86_64/loadbalancer/os',
      'content/eus/rhel/server/6/6.2/x86_64/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/optional/debug',
      'content/eus/rhel/server/6/6.2/x86_64/optional/os',
      'content/eus/rhel/server/6/6.2/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/os',
      'content/eus/rhel/server/6/6.2/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/6/6.2/x86_64/resilientstorage/os',
      'content/eus/rhel/server/6/6.2/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/scalablefilesystem/debug',
      'content/eus/rhel/server/6/6.2/x86_64/scalablefilesystem/os',
      'content/eus/rhel/server/6/6.2/x86_64/scalablefilesystem/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/6/6.2/s390x/debug',
      'content/eus/rhel/system-z/6/6.2/s390x/optional/debug',
      'content/eus/rhel/system-z/6/6.2/s390x/optional/os',
      'content/eus/rhel/system-z/6/6.2/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/6/6.2/s390x/os',
      'content/eus/rhel/system-z/6/6.2/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'php-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-3.el6_2.11', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.4/x86_64/debug',
      'content/aus/rhel/server/6/6.4/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.4/x86_64/optional/os',
      'content/aus/rhel/server/6/6.4/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.4/x86_64/os',
      'content/aus/rhel/server/6/6.4/x86_64/source/SRPMS',
      'content/eus/rhel/computenode/6/6.4/x86_64/debug',
      'content/eus/rhel/computenode/6/6.4/x86_64/optional/debug',
      'content/eus/rhel/computenode/6/6.4/x86_64/optional/os',
      'content/eus/rhel/computenode/6/6.4/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/6/6.4/x86_64/os',
      'content/eus/rhel/computenode/6/6.4/x86_64/sfs/debug',
      'content/eus/rhel/computenode/6/6.4/x86_64/sfs/os',
      'content/eus/rhel/computenode/6/6.4/x86_64/sfs/source/SRPMS',
      'content/eus/rhel/computenode/6/6.4/x86_64/source/SRPMS',
      'content/eus/rhel/power/6/6.4/ppc64/debug',
      'content/eus/rhel/power/6/6.4/ppc64/optional/debug',
      'content/eus/rhel/power/6/6.4/ppc64/optional/os',
      'content/eus/rhel/power/6/6.4/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/6/6.4/ppc64/os',
      'content/eus/rhel/power/6/6.4/ppc64/source/SRPMS',
      'content/eus/rhel/server/6/6.4/i386/debug',
      'content/eus/rhel/server/6/6.4/i386/highavailability/debug',
      'content/eus/rhel/server/6/6.4/i386/highavailability/os',
      'content/eus/rhel/server/6/6.4/i386/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.4/i386/loadbalancer/debug',
      'content/eus/rhel/server/6/6.4/i386/loadbalancer/os',
      'content/eus/rhel/server/6/6.4/i386/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.4/i386/optional/debug',
      'content/eus/rhel/server/6/6.4/i386/optional/os',
      'content/eus/rhel/server/6/6.4/i386/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.4/i386/os',
      'content/eus/rhel/server/6/6.4/i386/resilientstorage/debug',
      'content/eus/rhel/server/6/6.4/i386/resilientstorage/os',
      'content/eus/rhel/server/6/6.4/i386/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.4/i386/source/SRPMS',
      'content/eus/rhel/server/6/6.4/x86_64/debug',
      'content/eus/rhel/server/6/6.4/x86_64/highavailability/debug',
      'content/eus/rhel/server/6/6.4/x86_64/highavailability/os',
      'content/eus/rhel/server/6/6.4/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.4/x86_64/loadbalancer/debug',
      'content/eus/rhel/server/6/6.4/x86_64/loadbalancer/os',
      'content/eus/rhel/server/6/6.4/x86_64/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.4/x86_64/optional/debug',
      'content/eus/rhel/server/6/6.4/x86_64/optional/os',
      'content/eus/rhel/server/6/6.4/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.4/x86_64/os',
      'content/eus/rhel/server/6/6.4/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/6/6.4/x86_64/resilientstorage/os',
      'content/eus/rhel/server/6/6.4/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.4/x86_64/scalablefilesystem/debug',
      'content/eus/rhel/server/6/6.4/x86_64/scalablefilesystem/os',
      'content/eus/rhel/server/6/6.4/x86_64/scalablefilesystem/source/SRPMS',
      'content/eus/rhel/server/6/6.4/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/6/6.4/s390x/debug',
      'content/eus/rhel/system-z/6/6.4/s390x/optional/debug',
      'content/eus/rhel/system-z/6/6.4/s390x/optional/os',
      'content/eus/rhel/system-z/6/6.4/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/6/6.4/s390x/os',
      'content/eus/rhel/system-z/6/6.4/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'php-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-23.el6_4.1', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/eus/rhel/computenode/6/6.3/x86_64/debug',
      'content/eus/rhel/computenode/6/6.3/x86_64/optional/debug',
      'content/eus/rhel/computenode/6/6.3/x86_64/optional/os',
      'content/eus/rhel/computenode/6/6.3/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/6/6.3/x86_64/os',
      'content/eus/rhel/computenode/6/6.3/x86_64/sfs/debug',
      'content/eus/rhel/computenode/6/6.3/x86_64/sfs/os',
      'content/eus/rhel/computenode/6/6.3/x86_64/sfs/source/SRPMS',
      'content/eus/rhel/computenode/6/6.3/x86_64/source/SRPMS',
      'content/eus/rhel/power/6/6.3/ppc64/debug',
      'content/eus/rhel/power/6/6.3/ppc64/optional/debug',
      'content/eus/rhel/power/6/6.3/ppc64/optional/os',
      'content/eus/rhel/power/6/6.3/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/6/6.3/ppc64/os',
      'content/eus/rhel/power/6/6.3/ppc64/source/SRPMS',
      'content/eus/rhel/server/6/6.3/i386/debug',
      'content/eus/rhel/server/6/6.3/i386/highavailability/debug',
      'content/eus/rhel/server/6/6.3/i386/highavailability/os',
      'content/eus/rhel/server/6/6.3/i386/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.3/i386/loadbalancer/debug',
      'content/eus/rhel/server/6/6.3/i386/loadbalancer/os',
      'content/eus/rhel/server/6/6.3/i386/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.3/i386/optional/debug',
      'content/eus/rhel/server/6/6.3/i386/optional/os',
      'content/eus/rhel/server/6/6.3/i386/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.3/i386/os',
      'content/eus/rhel/server/6/6.3/i386/resilientstorage/debug',
      'content/eus/rhel/server/6/6.3/i386/resilientstorage/os',
      'content/eus/rhel/server/6/6.3/i386/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.3/i386/source/SRPMS',
      'content/eus/rhel/server/6/6.3/x86_64/debug',
      'content/eus/rhel/server/6/6.3/x86_64/highavailability/debug',
      'content/eus/rhel/server/6/6.3/x86_64/highavailability/os',
      'content/eus/rhel/server/6/6.3/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.3/x86_64/loadbalancer/debug',
      'content/eus/rhel/server/6/6.3/x86_64/loadbalancer/os',
      'content/eus/rhel/server/6/6.3/x86_64/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.3/x86_64/optional/debug',
      'content/eus/rhel/server/6/6.3/x86_64/optional/os',
      'content/eus/rhel/server/6/6.3/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.3/x86_64/os',
      'content/eus/rhel/server/6/6.3/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/6/6.3/x86_64/resilientstorage/os',
      'content/eus/rhel/server/6/6.3/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.3/x86_64/scalablefilesystem/debug',
      'content/eus/rhel/server/6/6.3/x86_64/scalablefilesystem/os',
      'content/eus/rhel/server/6/6.3/x86_64/scalablefilesystem/source/SRPMS',
      'content/eus/rhel/server/6/6.3/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/6/6.3/s390x/debug',
      'content/eus/rhel/system-z/6/6.3/s390x/optional/debug',
      'content/eus/rhel/system-z/6/6.3/s390x/optional/os',
      'content/eus/rhel/system-z/6/6.3/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/6/6.3/s390x/os',
      'content/eus/rhel/system-z/6/6.3/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'php-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-14.el6_3.3', 'sp':'3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
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
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php / php-bcmath / php-cli / php-common / php-dba / php-devel / etc');
}
