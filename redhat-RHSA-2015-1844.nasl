#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1844. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119363);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2015-1806",
    "CVE-2015-1807",
    "CVE-2015-1808",
    "CVE-2015-1809",
    "CVE-2015-1810",
    "CVE-2015-1811",
    "CVE-2015-1812",
    "CVE-2015-1813",
    "CVE-2015-1814"
  );
  script_xref(name:"RHSA", value:"2015:1844");

  script_name(english:"RHEL 6 : Red Hat OpenShift Enterprise 2.2.7 (RHSA-2015:1844)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2015:1844 advisory.

    OpenShift Enterprise by Red Hat is the company's cloud computing
    Platform-as-a-Service (PaaS) solution designed for on-premise or
    private cloud deployments.

    Space precludes documenting all of the bug fixes in this advisory.
    See the OpenShift Enterprise Technical Notes, which will be updated
    shortly for release 2.2.7, for details about these changes. The
    following security issues are addressed in this release:

    A flaw was found in the Jenkins API token-issuing service. The
    service was not properly protected against anonymous users,
    potentially allowing remote attackers to escalate privileges.
    (CVE-2015-1814)

    It was found that the combination filter Groovy script could allow
    a remote attacker to potentially execute arbitrary code on a
    Jenkins master. (CVE-2015-1806)

    It was found that when building artifacts, the Jenkins server would
    follow symbolic links, potentially resulting in disclosure of
    information on the server. (CVE-2015-1807)

    A denial of service flaw was found in the way Jenkins handled
    certain update center data. An authenticated user could provide
    specially crafted update center data to Jenkins, causing plug-in
    and tool installation to not work properly. (CVE-2015-1808)

    It was found that Jenkins' XPath handling allowed XML External
    Entity (XXE) expansion. A remote attacker with read access could
    use this flaw to read arbitrary XML files on the Jenkins server.
    (CVE-2015-1809)

    It was discovered that the internal Jenkins user database did not
    restrict access to reserved names, allowing users to escalate
    privileges. (CVE-2015-1810)

    It was found that Jenkins' XML handling allowed XML External Entity
    (XXE) expansion. A remote attacker with the ability to pass XML
    data to Jenkins could use this flaw to read arbitrary XML files on
    the Jenkins server. (CVE-2015-1811)

    Two cross-site scripting (XSS) flaws were found in Jenkins. A
    remote  attacker could use these flaws to conduct XSS attacks
    against users of an application using Jenkins. (CVE-2015-1812,
    CVE-2015-1813)

    https://access.redhat.com/documentation/en-US/OpenShift_Enterprise/2/html-
    single/Technical_Notes/index.html
    All OpenShift Enterprise 2 users are advised to upgrade to these
    updated packages.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2015/rhsa-2015_1844.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d824e348");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2015:1844");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1062253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1128567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1130028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1138522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1152524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1160699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1171815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1191283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1197123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1197576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1216206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1217572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1221931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1225943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1226061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1227501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1228373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1229300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1232827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1232921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1241750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1257757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1264039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1264210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1264216");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1814");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-1811");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 284, 59, 611, 79);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-diy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbosseap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbossews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-logshifter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-apache-vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-gear-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-msg-broker-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-routing-daemon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'jenkins-1.609.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-broker-1.16.2.10-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-broker-util-1.36.2.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-diy-1.26.1.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-haproxy-1.30.1.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-jbosseap-2.26.3.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-jbossews-1.34.3.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-jenkins-1.28.2.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-mock-1.22.1.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-nodejs-1.33.1.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-perl-1.30.1.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-php-1.34.1.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-python-1.33.3.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-ruby-1.32.1.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-logshifter-1.10.1.2-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-node-util-1.37.2.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rhc-1.37.1.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-console-1.35.2.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-controller-1.37.3.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-frontend-apache-vhost-0.12.4.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-gear-placement-0.0.2.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-msg-broker-mcollective-1.35.3.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-node-1.37.1.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-routing-daemon-0.25.1.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jenkins / openshift-origin-broker / openshift-origin-broker-util / etc');
}
