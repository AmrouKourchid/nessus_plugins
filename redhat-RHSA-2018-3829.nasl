#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3829. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119705);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id("CVE-2018-15727");
  script_xref(name:"RHSA", value:"2018:3829");

  script_name(english:"RHEL 7 : RHGS WA (RHSA-2018:3829)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for RHGS WA.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2018:3829 advisory.

    Red Hat Gluster Storage Web Administration includes a fully automated setup based on Ansible and provides
    deep metrics and insights into active Gluster storage pools by using the Grafana platform. Red Hat Gluster
    Storage Web Administration provides a dashboard view which allows an administrator to get a view of
    overall gluster health in terms of hosts, volumes, bricks, and other components of GlusterFS.

    Security Fix(es):

    * grafana: authentication bypass knowing only a username of an LDAP or OAuth user (CVE-2018-15727)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

    All users of Red Hat Gluster Storage Web Administration are advised to upgrade to these updated packages,
    which provide numerous bug fixes.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2018/rhsa-2018_3829.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ea62d9d");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:3829");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1599291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1610668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1611991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1624088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1627651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1627988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1629520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1630344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1641413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1642574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1650557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1656057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1656064");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL RHGS WA package based on the guidance in RHSA-2018:3829.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15727");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tendrl-gluster-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tendrl-grafana-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tendrl-monitoring-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tendrl-node-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tendrl-ui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tendrl-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tendrl-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tendrl-api-httpd");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/rhgs-webadmin-agent/3.1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhgs-webadmin-agent/3.1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhgs-webadmin-agent/3.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'tendrl-gluster-integration-1.6.3-13.el7rhgs', 'release':'7', 'el_string':'el7rhgs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/rhgs-webadmin-agent/3.1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhgs-webadmin-agent/3.1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhgs-webadmin-agent/3.1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhgs-webadmin/3.1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhgs-webadmin/3.1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhgs-webadmin/3.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'tendrl-node-agent-1.6.3-11.el7rhgs', 'release':'7', 'el_string':'el7rhgs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/rhgs-webadmin/3.1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhgs-webadmin/3.1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhgs-webadmin/3.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'grafana-4.6.4-1.el7rhgs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7rhgs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'tendrl-ansible-1.6.3-10.el7rhgs', 'release':'7', 'el_string':'el7rhgs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'tendrl-api-1.6.3-8.el7rhgs', 'release':'7', 'el_string':'el7rhgs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'tendrl-api-httpd-1.6.3-8.el7rhgs', 'release':'7', 'el_string':'el7rhgs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'tendrl-grafana-plugins-1.6.3-16.el7rhgs', 'release':'7', 'el_string':'el7rhgs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'tendrl-monitoring-integration-1.6.3-16.el7rhgs', 'release':'7', 'el_string':'el7rhgs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'tendrl-ui-1.6.3-14.el7rhgs', 'release':'7', 'el_string':'el7rhgs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grafana / tendrl-ansible / tendrl-api / tendrl-api-httpd / etc');
}
