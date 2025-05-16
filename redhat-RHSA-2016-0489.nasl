#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0489. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119368);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2015-5254",
    "CVE-2015-5317",
    "CVE-2015-5318",
    "CVE-2015-5319",
    "CVE-2015-5320",
    "CVE-2015-5321",
    "CVE-2015-5322",
    "CVE-2015-5323",
    "CVE-2015-5324",
    "CVE-2015-5325",
    "CVE-2015-5326",
    "CVE-2015-7537",
    "CVE-2015-7538",
    "CVE-2015-7539",
    "CVE-2015-8103"
  );
  script_xref(name:"RHSA", value:"2016:0489");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"RHEL 6 : Red Hat OpenShift Enterprise 2.2.9 (RHSA-2016:0489)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2016:0489 advisory.

    OpenShift Enterprise by Red Hat is the company's cloud computing
    Platform-as-a-Service (PaaS) solution designed for on-premise or
    private cloud deployments.

    The following security issue is addressed with this release:

    It was found that ActiveMQ did not safely handle user supplied data
    when deserializing objects. A remote attacker could use this flaw to
    execute arbitrary code with the permissions of the ActiveMQ
    application. (CVE-2015-5254)

    An update for Jenkins Continuous Integration Server that addresses a
    large number of security issues including XSS, CSRF, information
    disclosure and code execution have been addressed as well.
    (CVE-2015-5317, CVE-2015-5318, CVE-2015-5319, CVE-2015-5320,
    CVE-2015-5321, CVE-2015-5322, CVE-2015-5323, CVE-2015-5324,
    CVE-2015-5325, CVE-2015-5326, CVE-2015-7537, CVE-2015-7538,
    CVE-2015-7539, CVE-2015-8103)

    Space precludes documenting all of the bug fixes in this advisory. See
    the OpenShift Enterprise Technical Notes, which will be updated
    shortly for release 2.2.9, for details about these changes:

    https://access.redhat.com/documentation/en-US/OpenShift_Enterprise/2/html-
    single/Technical_Notes/index.html

    All OpenShift Enterprise 2 users are advised to upgrade to these
    updated packages.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2016/rhsa-2016_0489.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c398eee2");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:0489");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1111456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1140816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1160934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1168480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1169690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1265423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1265811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1279584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1283372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1291292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1291795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1291797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1291798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1294513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1299014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1299095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1305688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1307174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1307175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1308716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1308718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1308720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1308722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1308739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1310247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1310266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1310841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1314535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1314546");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7539");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-8103");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenNMS Java Object Unserialization Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(352, 502, 79);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:activemq-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-yum-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-msg-node-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-apache-vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-node");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:activemq");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'activemq-5.9.0-6.redhat.611454.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'activemq-client-5.9.0-6.redhat.611454.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'jenkins-1.625.3-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-release-2.2.9-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-upgrade-broker-2.2.9-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-upgrade-node-2.2.9-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-yum-validator-2.2.9-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-broker-util-1.37.5.3-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-cron-1.25.2.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-haproxy-1.31.5.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-mysql-1.31.2.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-php-1.35.3.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-python-1.34.2.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-msg-node-mcollective-1.30.2.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-node-proxy-1.26.2.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-node-util-1.38.6.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-bcmath-5.3.3-46.el6_7.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-devel-5.3.3-46.el6_7.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-fpm-5.3.3-46.el6_7.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-imap-5.3.3-46.el6_7.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-intl-5.3.3-46.el6_7.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-mbstring-5.3.3-46.el6_7.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-process-5.3.3-46.el6_7.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rhc-1.38.6.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-common-1.29.5.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-console-1.35.5.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-controller-1.38.5.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-frontend-apache-vhost-0.13.2.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-node-1.38.5.3-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'activemq / activemq-client / jenkins / openshift-enterprise-release / etc');
}
