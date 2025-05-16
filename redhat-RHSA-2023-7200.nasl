#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:7200. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191069);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2023-39325", "CVE-2023-39326", "CVE-2023-45287");
  script_xref(name:"RHSA", value:"2023:7200");

  script_name(english:"RHEL 9 : OpenShift Container Platform 4.15.z (RHSA-2023:7200)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for OpenShift Container Platform 4.15.z.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:7200 advisory.

    Red Hat build of MicroShift is Red Hat's light-weight Kubernetes orchestration solution designed for edge
    device deployments and is built from the edge capabilities of Red Hat OpenShift. MicroShift is an
    application that is deployed on top of Red Hat Enterprise Linux devices at
    the edge, providing an efficient way to operate single-node clusters in these low-resource environments.

    This advisory contains the RPM packages for Red Hat build of MicroShift 4.15.0. Read the following
    advisory for the container images for this
    release:

    https://access.redhat.com/errata/RHSA-2023:7198

    Security Fix(es):

    * golang: net/http, x/net/http2: rapid stream resets can cause excessive work (CVE-2023-44487)
    (CVE-2023-39325)

    * golang: net/http/internal: Denial of Service (DoS) via Resource Consumption via HTTP requests
    (CVE-2023-39326)

    * golang: crypto/tls: Timing Side Channel attack in RSA based TLS key exchanges. (CVE-2023-45287)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2023_7200.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cf2526b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/RHSB-2023-003");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:7200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253330");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-18548");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-19288");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-19363");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-19384");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-19422");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-19433");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-19457");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-19488");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-19540");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-19567");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-19632");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-19719");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-20037");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-22322");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-22338");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-22685");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-22809");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-22854");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-22858");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-22936");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-25689");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-25851");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-25904");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-27398");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-27855");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL OpenShift Container Platform 4.15.z package based on the guidance in RHSA-2023:7200.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45287");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(208, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:microshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:microshift-greenboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:microshift-networking");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:microshift-olm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:microshift-release-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:microshift-selinux");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/rhocp/4.15/debug',
      'content/dist/layered/rhel9/aarch64/rhocp/4.15/os',
      'content/dist/layered/rhel9/aarch64/rhocp/4.15/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhocp/4.15/debug',
      'content/dist/layered/rhel9/x86_64/rhocp/4.15/os',
      'content/dist/layered/rhel9/x86_64/rhocp/4.15/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'microshift-4.15.0-202402260721.p0.g799289b.assembly.4.15.0.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'microshift-4.15.0-202402260721.p0.g799289b.assembly.4.15.0.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'microshift-greenboot-4.15.0-202402260721.p0.g799289b.assembly.4.15.0.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'microshift-networking-4.15.0-202402260721.p0.g799289b.assembly.4.15.0.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'microshift-networking-4.15.0-202402260721.p0.g799289b.assembly.4.15.0.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'microshift-olm-4.15.0-202402260721.p0.g799289b.assembly.4.15.0.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'microshift-olm-4.15.0-202402260721.p0.g799289b.assembly.4.15.0.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'microshift-release-info-4.15.0-202402260721.p0.g799289b.assembly.4.15.0.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'microshift-selinux-4.15.0-202402260721.p0.g799289b.assembly.4.15.0.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'microshift / microshift-greenboot / microshift-networking / etc');
}
