#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:0777. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193747);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2020-7692",
    "CVE-2022-1471",
    "CVE-2022-2048",
    "CVE-2022-25857",
    "CVE-2022-30946",
    "CVE-2022-30952",
    "CVE-2022-30953",
    "CVE-2022-30954",
    "CVE-2022-34174",
    "CVE-2022-36882",
    "CVE-2022-36883",
    "CVE-2022-36884",
    "CVE-2022-36885",
    "CVE-2022-43401",
    "CVE-2022-43402",
    "CVE-2022-43403",
    "CVE-2022-43404",
    "CVE-2022-43405",
    "CVE-2022-43406",
    "CVE-2022-43407",
    "CVE-2022-43408",
    "CVE-2022-43409",
    "CVE-2022-45047",
    "CVE-2022-45379",
    "CVE-2022-45380",
    "CVE-2022-45381"
  );
  script_xref(name:"RHSA", value:"2023:0777");

  script_name(english:"RHEL 8 : OpenShift Container Platform 4.9.56 (RHSA-2023:0777)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for OpenShift Container Platform 4.9.56.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:0777 advisory.

    Red Hat OpenShift Container Platform is Red Hat's cloud computing Kubernetes application platform solution
    designed for on-premise or private cloud deployments.

    This advisory contains the RPM packages for Red Hat OpenShift Container Platform 4.9.56. See the following
    advisory for the container images for this release:

    https://access.redhat.com/errata/RHSA-2023:0778

    Security Fix(es):

    * jenkins-plugin/script-security: Sandbox bypass vulnerabilities in Jenkins Script Security Plugin
    (CVE-2022-43401)

    * jenkins-plugin/workflow-cps: Sandbox bypass vulnerabilities in Pipeline: Groovy Plugin (CVE-2022-43402)

    * jenkins-plugin/script-security: Sandbox bypass vulnerabilities in Jenkins Script Security Plugin
    (CVE-2022-43403)

    * jenkins-plugin/script-security: Sandbox bypass vulnerabilities in Jenkins Script Security Plugin
    (CVE-2022-43404)

    * jenkins-plugin/pipeline-groovy-lib: Sandbox bypass vulnerability in Pipeline: Groovy Libraries Plugin
    (CVE-2022-43405)

    * jenkins-plugin/workflow-cps-global-lib: Sandbox bypass vulnerability in Pipeline: Deprecated Groovy
    Libraries Plugin (CVE-2022-43406)

    * google-oauth-client: missing PKCE support in accordance with the RFC for OAuth 2.0 for Native Apps can
    lead to improper authorization (CVE-2020-7692)

    * SnakeYaml: Constructor Deserialization Remote Code Execution (CVE-2022-1471)

    * snakeyaml: Denial of Service due to missing nested depth limitation for collections (CVE-2022-25857)

    * jenkins-plugin/pipeline-input-step: CSRF protection for any URL can be bypassed in Pipeline: Input Step
    Plugin (CVE-2022-43407)

    * mina-sshd: Java unsafe deserialization vulnerability (CVE-2022-45047)

    * jenkins-plugin/script-security: Whole-script approval in Script Security Plugin vulnerable to SHA-1
    collisions (CVE-2022-45379)

    * jenkins-plugin/JUnit: Stored XSS vulnerability in JUnit Plugin (CVE-2022-45380)

    * jenkins-plugin/pipeline-utility-steps: Arbitrary file read vulnerability in Pipeline Utility Steps
    Plugin (CVE-2022-45381)

    * http2-server: Invalid HTTP/2 requests cause DoS (CVE-2022-2048)

    * Jenkins plugin: CSRF vulnerability in Script Security Plugin (CVE-2022-30946)

    * Jenkins plugin: User-scoped credentials exposed to other users by Pipeline SCM API for Blue Ocean Plugin
    (CVE-2022-30952)

    * Jenkins plugin: CSRF vulnerability in Blue Ocean Plugin (CVE-2022-30953)

    * Jenkins plugin: missing permission checks in Blue Ocean Plugin (CVE-2022-30954)

    * jenkins: Observable timing discrepancy allows determining username validity (CVE-2022-34174)

    * jenkins-plugin: Cross-site Request Forgery (CSRF) in org.jenkins-ci.plugins:git (CVE-2022-36882)

    * jenkins plugin: Lack of authentication mechanism in Git Plugin webhook (CVE-2022-36883)

    * jenkins plugin: Lack of authentication mechanism in Git Plugin webhook (CVE-2022-36884)

    * jenkins plugin: Non-constant time webhook signature comparison in GitHub Plugin (CVE-2022-36885)

    * jenkins-plugin/pipeline-stage-view: CSRF protection for any URL can be bypassed in Pipeline: Stage View
    Plugin (CVE-2022-43408)

    * jenkins-plugin/workflow-support: Stored XSS vulnerability in Pipeline: Supporting APIs Plugin
    (CVE-2022-43409)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    All OpenShift Container Platform 4.9 users are advised to upgrade to these updated packages and images
    when they are available in the appropriate release channel. To check for available updates, use the
    OpenShift CLI (oc) or web console. Instructions for upgrading a cluster are available at
    https://docs.openshift.com/container-platform/4.9/updating/updating-cluster-cli.html

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_0777.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?892193cb");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  # https://docs.openshift.com/container-platform/4.9/release_notes/ocp-4-9-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc25b68c");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1856376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2116840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2116952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2119643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2119645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2119646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2119647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2119653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2119656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2119657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2119658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2126789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2143086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2143089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2143090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2145194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2150009");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:0777");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL OpenShift Container Platform 4.9.56 package based on the guidance in RHSA-2023:0777.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7692");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-43406");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 200, 208, 328, 352, 358, 400, 410, 502, 668, 693, 838, 862);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-2-plugins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/aarch64/rhocp/4.9/debug',
      'content/dist/layered/rhel8/aarch64/rhocp/4.9/os',
      'content/dist/layered/rhel8/aarch64/rhocp/4.9/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.9/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.9/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.9/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.9/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.9/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.9/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.9/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.9/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.9/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jenkins-2-plugins-4.9.1675668922-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-7692', 'CVE-2022-1471', 'CVE-2022-25857', 'CVE-2022-30946', 'CVE-2022-30952', 'CVE-2022-30953', 'CVE-2022-30954', 'CVE-2022-36882', 'CVE-2022-36883', 'CVE-2022-36884', 'CVE-2022-36885', 'CVE-2022-43401', 'CVE-2022-43402', 'CVE-2022-43403', 'CVE-2022-43404', 'CVE-2022-43405', 'CVE-2022-43406', 'CVE-2022-43407', 'CVE-2022-43408', 'CVE-2022-43409', 'CVE-2022-45047', 'CVE-2022-45379', 'CVE-2022-45380', 'CVE-2022-45381']},
      {'reference':'jenkins-2.361.1.1675668150-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-2048', 'CVE-2022-34174']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jenkins / jenkins-2-plugins');
}
