#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2666. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119366);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/03");

  script_cve_id("CVE-2015-3281");
  script_xref(name:"RHSA", value:"2015:2666");

  script_name(english:"RHEL 6 : Red Hat OpenShift Enterprise 2.2.8 (RHSA-2015:2666)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2015:2666 advisory.

    OpenShift Enterprise by Red Hat is the company's cloud computing
    Platform-as-a-Service (PaaS) solution designed for on-premise or
    private cloud deployments.

    The following security issue is addressed with this release:

    An implementation error related to the memory management of request
    and responses was found within HAProxy's buffer_slow_realign()
    function. An unauthenticated remote attacker could use this flaw
    to leak certain memory buffer contents from a past request or
    session. (CVE-2015-3281)

    Space precludes documenting all of the bug fixes in this advisory. See
    the OpenShift Enterprise Technical Notes, which will be updated
    shortly for release 2.2.8, for details about these changes:

    https://access.redhat.com/documentation/en-US/OpenShift_Enterprise/2/html-
    single/Technical_Notes/index.html

    All OpenShift Enterprise 2 users are advised to upgrade to these updated
    packages.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2015/rhsa-2015_2666.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36b2fcc7");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2015:2666");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1045226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1054441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1064039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1101973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1110415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1111501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1111598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1139608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1140766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1155003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1177753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1211526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1218872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1239072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1241675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1248439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1255426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1264722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1265609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1268080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1270660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1271338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1272195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1277695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1280438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282940");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3281");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy15side");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-yum-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbosseap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbossews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-routing-daemon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
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
      {'reference':'haproxy15side-1.5.4-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-release-2.2.8-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-upgrade-broker-2.2.8-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-upgrade-node-2.2.8-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-yum-validator-2.2.8-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-broker-util-1.37.4.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-haproxy-1.31.4.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-jbosseap-2.27.3.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-jbossews-1.35.3.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-python-1.34.1.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-node-util-1.38.5.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rhc-1.38.4.5-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-common-1.29.4.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-controller-1.38.4.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-node-1.38.4.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-routing-daemon-0.26.4.4-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'}
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'haproxy15side / openshift-enterprise-release / etc');
}
