#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:5406. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205554);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2024-43044");
  script_xref(name:"RHSA", value:"2024:5406");

  script_name(english:"RHEL 8 : Red Hat Product OCP Tools 4.13 OpenShift Jenkins (RHSA-2024:5406)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for Red Hat Product OCP Tools 4.13 OpenShift Jenkins.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2024:5406 advisory.

    Jenkins is a continuous integration server that monitors executions of repeated jobs, such as building a
    software project or jobs run by cron.

    Security Fix(es):

    * jenkins: Arbitrary file read vulnerability through agent connections can lead to RCE (CVE-2024-43044)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_5406.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ce05547");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2145194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303466");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JKNS-271");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JKNS-289");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JKNS-397");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JKNS-398");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-10934");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-11158");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-11329");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-11446");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-11452");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-1357");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-13651");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-13870");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-14112");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-14311");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-14634");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-15647");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-15986");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-1709");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-1942");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-2099");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-2184");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-2318");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-27389");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-28962");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-655");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-6579");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-6870");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-710");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-8377");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-8442");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPTOOLS-245");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:5406");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat Product OCP Tools 4.13 OpenShift Jenkins package based on the guidance in RHSA-2024:5406.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43044");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/14");

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
      'content/dist/layered/rhel8/aarch64/ocp-tools/4.13/debug',
      'content/dist/layered/rhel8/aarch64/ocp-tools/4.13/os',
      'content/dist/layered/rhel8/aarch64/ocp-tools/4.13/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ocp-tools/4.13/debug',
      'content/dist/layered/rhel8/ppc64le/ocp-tools/4.13/os',
      'content/dist/layered/rhel8/ppc64le/ocp-tools/4.13/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ocp-tools/4.13/debug',
      'content/dist/layered/rhel8/s390x/ocp-tools/4.13/os',
      'content/dist/layered/rhel8/s390x/ocp-tools/4.13/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ocp-tools/4.13/debug',
      'content/dist/layered/rhel8/x86_64/ocp-tools/4.13/os',
      'content/dist/layered/rhel8/x86_64/ocp-tools/4.13/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jenkins-2-plugins-4.13.1723446018-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jenkins-2.462.1.1723445923-3.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jenkins / jenkins-2-plugins');
}
