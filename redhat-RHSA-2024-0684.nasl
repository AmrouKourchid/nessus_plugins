#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:0684. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190222);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2024-21626");
  script_xref(name:"IAVA", value:"2024-A-0071");
  script_xref(name:"RHSA", value:"2024:0684");

  script_name(english:"RHEL 8 : OpenShift Container Platform 4.11.58 (RHSA-2024:0684)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for OpenShift Container Platform 4.11.58.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has a package installed that is affected by a vulnerability as referenced in
the RHSA-2024:0684 advisory.

    Red Hat OpenShift Container Platform is Red Hat's cloud computing Kubernetes application platform solution
    designed for on-premise or private
    cloud deployments.

    This advisory contains the RPM packages for Red Hat OpenShift Container
    Platform 4.11.58. See the following advisory for the container images for
    this release:

    https://access.redhat.com/errata/RHSA-2024:0682

    All OpenShift Container Platform 4.11 users are advised to upgrade to these
    updated packages and images when they are available in the appropriate
    release channel. To check for available updates, use the OpenShift Console
    or the CLI oc command. Instructions for upgrading a cluster are available
    at
    https://docs.openshift.com/container-platform/4.11/updating/updating-cluster-cli.html

    Security Fix(es):

    * runc: file descriptor leak Leaky Vessels (CVE-2024-21626)

    A Red Hat Security Bulletin which addresses further details about the Leaky Vessels flaw is available in
    the References section.

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    All OpenShift Container Platform 4.11 users are advised to upgrade to these updated packages and images
    when they are available in the appropriate release channel. To check for available updates, use the
    OpenShift CLI (oc) or web console. Instructions for upgrading a cluster are available at
    https://docs.openshift.com/container-platform/4.11/updating/updating-cluster-cli.html

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_0684.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?067dc815");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/RHSB-2024-001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258725");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:0684");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL OpenShift Container Platform 4.11.58 packages based on the guidance in RHSA-2024:0684.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21626");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'runc (docker) File Descriptor Leak Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(200);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
      'content/dist/layered/rhel8/aarch64/rhocp/4.11/debug',
      'content/dist/layered/rhel8/aarch64/rhocp/4.11/os',
      'content/dist/layered/rhel8/aarch64/rhocp/4.11/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.11/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.11/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.11/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.11/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.11/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.11/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.11/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.11/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.11/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'runc-1.1.2-3.1.rhaos4.11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'runc');
}
