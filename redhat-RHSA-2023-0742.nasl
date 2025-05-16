#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:0742. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194206);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2021-44420", "CVE-2022-41323");
  script_xref(name:"RHSA", value:"2023:0742");

  script_name(english:"RHEL 8 : RHUI 4.3.0  - Security Fixes, Bug Fixes, and Enhancements Update (Low) (RHSA-2023:0742)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2023:0742 advisory.

    Red Hat Update Infrastructure (RHUI) offers a highly scalable, highly redundant framework that enables you
    to manage repositories and content. It also enables cloud providers to deliver content and updates to Red
    Hat Enterprise Linux (RHEL) instances.

    Security Fix(es):
    * Django: Potential bypass of an upstream access control based on URL paths (CVE-2021-44420)

    * Django: Potential denial-of-service vulnerability in internationalized URLs (CVE-2022-41323)

    This RHUI update fixes the following bugs:

    * Previously, `rhui-manager` failed to create an Alternate Content Source package. With this update, the
    problem is now fixed and you can successfully create an Alternate Content Source package.

    * With this update,  several parts of redundant code have been removed from RHUI. Most notably, the unused
    `entitlement` argument in the custom repository creation has been removed. Additionally, the Atomic and
    OSTree functions have been removed because these features have been deprecated in RHUI 4.

    * Previously, CDS and HAProxy management used a variable called `port`. However, this name is a reserved
    playbook keyword in Ansible. Consequently, Ansible printed warnings about the use of this variable. With
    this update, the variable has been renamed to `remote_port` which prevents the warnings.

    * Previously, when the RHUA installation playbook failed, `rhui-installer` exited with a status of 0,
    which normally indicates success. With this update, the problem has been fixed, and `rhui-installer` exits
    with a status of 1, indicating that the RHUA installation playbook has failed.

    * Previously, RHUI did not accept proxy server settings when adding container images. Consequently, RHUI
    was unable to synchronize container images if the proxy server configuration was required to access the
    container registries. With this update, RHUI now accepts proxy settings when they are configured with the
    container images. As a result, proxy-enabled RHUI environments can now synchronize container images.

    * With this update, the misaligned text on the repository workflow screen in the rhui-manager text
    interface has been fixed.

    This RHUI update introduces the following enhancements:

    * This update introduces a newer version of Pulp, `3.21.0`. Among other upstream bug fixes and
    enhancements, this version changes how Pulp manages ambiguous CDN repodata that contains a duplicate
    package name-version-release string. Instead of failing, Pulp logs a warning and allows the affected
    repository to be synchronized.(BZ#2134277)

    * A new `rhui-manager` command is now available, `rhui-manager [--noninteractive] cds reinstall --all`.
    With this command, you can reinstall all of your CDS nodes using a single command. Additionally, you do
    not need to specify any of the CDS host names.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_0742.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45ae8f8a");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#low");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2028178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2134277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136130");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-124");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-149");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-169");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-214");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-296");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-336");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-341");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-355");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-94");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:0742");
  script_set_attribute(attribute:"solution", value:
"Update the affected python39-django package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44420");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(290, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-django");
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
      'content/dist/layered/rhel8/x86_64/rhui/4/debug',
      'content/dist/layered/rhel8/x86_64/rhui/4/os',
      'content/dist/layered/rhel8/x86_64/rhui/4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python39-django-3.2.16-1.0.1.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python39-django');
}
