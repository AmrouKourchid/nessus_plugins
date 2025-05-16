#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:7201. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191072);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2023-39325",
    "CVE-2023-39326",
    "CVE-2023-45287",
    "CVE-2023-48795"
  );
  script_xref(name:"RHSA", value:"2023:7201");

  script_name(english:"RHEL 8 / 9 : OpenShift Container Platform 4.15.0 (RHSA-2023:7201)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for OpenShift Container Platform 4.15.0.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:7201 advisory.

    Red Hat OpenShift Container Platform is Red Hat's cloud computing
    Kubernetes application platform solution designed for on-premise or private
    cloud deployments.

    Security Fix(es):

    * golang: net/http, x/net/http2: rapid stream resets can cause excessive
    work (CVE-2023-44487) (CVE-2023-39325)
    * golang: net/http/internal: Denial of Service (DoS) via Resource
    Consumption via HTTP requests (CVE-2023-39326)
    * golang: crypto/tls: Timing Side Channel attack in RSA based TLS key
    exchanges. (CVE-2023-45287)
    * ssh: Prefix truncation attack on Binary Packet Protocol (BPP)
    (CVE-2023-48795)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    All OpenShift Container Platform 4.15 users are advised to upgrade to these updated packages and images
    when they are available in the appropriate release channel. To check for available updates, use the
    OpenShift CLI (oc) or web console. Instructions for upgrading a cluster are available at
    https://docs.openshift.com/container-platform/4.15/updating/updating_a_cluster/updating-cluster-cli.html

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2023_7201.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9a8ffd2");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/RHSB-2023-003");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:7201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2231370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2251198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258725");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL OpenShift Container Platform 4.15.0 packages based on the guidance in RHSA-2023:7201.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45287");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-48795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(208, 222, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:butane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:butane-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition-validate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
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
      'content/dist/layered/rhel8/x86_64/rhocp/4.15/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.15/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.15/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'buildah-1.29.1-20.2.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'buildah-tests-1.29.1-20.2.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'butane-0.20.0-1.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'butane-redistributable-0.20.0-1.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'containernetworking-plugins-1.4.0-1.1.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39325', 'CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'cri-o-1.28.3-14.rhaos4.15.git33aabd8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326']},
      {'reference':'cri-tools-1.28.0-3.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326']},
      {'reference':'openshift-clients-4.15.0-202402070507.p0.g48dcf59.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39325', 'CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'openshift-clients-redistributable-4.15.0-202402070507.p0.g48dcf59.assembly.stream.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39325', 'CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'openshift-hyperkube-4.15.0-202402142009.p0.g6216ea1.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39325', 'CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'podman-4.4.1-21.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'podman-catatonit-4.4.1-21.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'podman-docker-4.4.1-21.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'podman-gvproxy-4.4.1-21.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'podman-plugins-4.4.1-21.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'podman-remote-4.4.1-21.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'podman-tests-4.4.1-21.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'runc-1.1.12-1.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45287']},
      {'reference':'skopeo-1.11.2-21.1.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'skopeo-tests-1.11.2-21.1.rhaos4.15.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/rhocp/4.15/debug',
      'content/dist/layered/rhel9/x86_64/rhocp/4.15/os',
      'content/dist/layered/rhel9/x86_64/rhocp/4.15/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'buildah-1.29.1-20.2.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'buildah-tests-1.29.1-20.2.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'cri-o-1.28.3-14.rhaos4.15.git33aabd8.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326']},
      {'reference':'cri-tools-1.28.0-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326']},
      {'reference':'ignition-2.16.2-2.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326']},
      {'reference':'ignition-validate-2.16.2-2.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326']},
      {'reference':'openshift-clients-4.15.0-202402070507.p0.g48dcf59.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39325', 'CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'openshift-clients-redistributable-4.15.0-202402070507.p0.g48dcf59.assembly.stream.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39325', 'CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'openshift-hyperkube-4.15.0-202402142009.p0.g6216ea1.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39325', 'CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'podman-4.4.1-21.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'podman-docker-4.4.1-21.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'podman-gvproxy-4.4.1-21.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'podman-plugins-4.4.1-21.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'podman-remote-4.4.1-21.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'podman-tests-4.4.1-21.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287', 'CVE-2023-48795']},
      {'reference':'runc-1.1.12-1.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45287']},
      {'reference':'skopeo-1.11.2-21.1.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287']},
      {'reference':'skopeo-tests-1.11.2-21.1.rhaos4.15.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-39326', 'CVE-2023-45287']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-tests / butane / butane-redistributable / etc');
}
