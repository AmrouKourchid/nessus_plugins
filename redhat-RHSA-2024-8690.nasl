#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:8690. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210527);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id(
    "CVE-2024-9341",
    "CVE-2024-9675",
    "CVE-2024-9676",
    "CVE-2024-34155",
    "CVE-2024-34156",
    "CVE-2024-34158"
  );
  script_xref(name:"RHSA", value:"2024:8690");

  script_name(english:"RHEL 8 / 9 : OpenShift Container Platform 4.13.53 (RHSA-2024:8690)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for OpenShift Container Platform 4.13.53.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:8690 advisory.

    Red Hat OpenShift Container Platform is Red Hat's cloud computing Kubernetes application platform solution
    designed for on-premise or private cloud deployments.

    This advisory contains the container images for Red Hat OpenShift Container Platform 4.13.53. See the
    following advisory for the RPM packages for this release:

    https://access.redhat.com/errata/RHSA-2024:8688

    Security Fix(es):

    * buildah: Buildah allows arbitrary directory mount (CVE-2024-9675)
    * encoding/gob: golang: Calling Decoder.Decode on a message which contains
    deeply nested structures can cause a panic due to stack exhaustion
    (CVE-2024-34156)
    * Podman: Buildah: cri-o: FIPS Crypto-Policy Directory Mounting Issue in
    containers/common Go Library (CVE-2024-9341)
    * Podman: Buildah: CRI-O: symlink traversal vulnerability in the
    containers/storage library can cause Denial of Service (DoS)
    (CVE-2024-9676)
    * go/parser: golang: Calling any of the Parse functions containing deeply
    nested literals can cause a panic/stack exhaustion (CVE-2024-34155)
    * go/build/constraint: golang: Calling Parse on a // +build build tag
    line with deeply nested expressions can cause a panic due to stack
    exhaustion (CVE-2024-34158)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    All OpenShift Container Platform 4.13 users are advised to upgrade to these updated packages and images
    when they are available in the appropriate release channel. To check for available updates, use the
    OpenShift CLI (oc) or web console. Instructions for upgrading a cluster are available at
    https://docs.openshift.com/container-platform/4.13/updating/updating-cluster-cli.html

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2315691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317467");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_8690.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82a9a295");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:8690");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL OpenShift Container Platform 4.13.53 packages based on the guidance in RHSA-2024:8690.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9341");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 59, 674, 1325);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-tests");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/aarch64/rhocp/4.13/debug',
      'content/dist/layered/rhel8/aarch64/rhocp/4.13/os',
      'content/dist/layered/rhel8/aarch64/rhocp/4.13/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.13/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.13/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.13/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.13/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.13/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.13/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.13/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.13/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.13/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'containernetworking-plugins-1.4.0-5.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-34156']},
      {'reference':'cri-o-1.26.5-26.rhaos4.13.giteb3d487.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9341', 'CVE-2024-9676']},
      {'reference':'podman-4.4.1-15.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'podman-catatonit-4.4.1-15.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'podman-docker-4.4.1-15.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'podman-gvproxy-4.4.1-15.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'podman-plugins-4.4.1-15.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'podman-remote-4.4.1-15.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'podman-tests-4.4.1-15.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'skopeo-1.11.3-4.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-34156']},
      {'reference':'skopeo-tests-1.11.3-4.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-34156']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/rhocp/4.13/debug',
      'content/dist/layered/rhel9/aarch64/rhocp/4.13/os',
      'content/dist/layered/rhel9/aarch64/rhocp/4.13/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/rhocp/4.13/debug',
      'content/dist/layered/rhel9/ppc64le/rhocp/4.13/os',
      'content/dist/layered/rhel9/ppc64le/rhocp/4.13/source/SRPMS',
      'content/dist/layered/rhel9/s390x/rhocp/4.13/debug',
      'content/dist/layered/rhel9/s390x/rhocp/4.13/os',
      'content/dist/layered/rhel9/s390x/rhocp/4.13/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhocp/4.13/debug',
      'content/dist/layered/rhel9/x86_64/rhocp/4.13/os',
      'content/dist/layered/rhel9/x86_64/rhocp/4.13/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'cri-o-1.26.5-26.rhaos4.13.giteb3d487.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9341', 'CVE-2024-9676']},
      {'reference':'podman-4.4.1-16.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'podman-docker-4.4.1-16.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'podman-gvproxy-4.4.1-16.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'podman-plugins-4.4.1-16.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'podman-remote-4.4.1-16.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'podman-tests-4.4.1-16.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-9675', 'CVE-2024-34155', 'CVE-2024-34156', 'CVE-2024-34158']},
      {'reference':'skopeo-1.11.3-4.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-34156']},
      {'reference':'skopeo-tests-1.11.3-4.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-34156']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'containernetworking-plugins / cri-o / podman / podman-catatonit / etc');
}
