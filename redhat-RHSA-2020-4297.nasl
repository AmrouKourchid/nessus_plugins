##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4297. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142002);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2019-16541",
    "CVE-2020-2252",
    "CVE-2020-2254",
    "CVE-2020-2255",
    "CVE-2020-8564",
    "CVE-2020-14040",
    "CVE-2020-14370",
    "CVE-2020-15586",
    "CVE-2020-16845"
  );
  script_xref(name:"RHSA", value:"2020:4297");
  script_xref(name:"IAVB", value:"2020-B-0060-S");

  script_name(english:"RHEL 7 / 8 : OpenShift Container Platform 4.6.1 (RHSA-2020:4297)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for OpenShift Container Platform 4.6.1.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4297 advisory.

    The podman tool manages pods, container images, and containers. It is part of the libpod library, which is
    for applications that use container pods. Container pods is a concept in Kubernetes.

    The runC tool is a lightweight, portable implementation of the Open Container Format (OCF) that provides
    container runtime.

    The skopeo command lets you inspect images from container image registries, get images and image layers,
    and use signatures to create and verify files.

    Security Fix(es):

    * jenkins-jira-plugin: plugin information disclosure (CVE-2019-16541)

    * jenkins-2-plugins/mailer: Missing hostname validation in Mailer Plugin could result in MITM
    (CVE-2020-2252)

    * jenkins-2-plugins/blueocean: Path traversal vulnerability in Blue Ocean Plugin could allow to read
    arbitrary files (CVE-2020-2254)

    * jenkins-2-plugins/blueocean: Blue Ocean Plugin does not perform permission checks in several HTTP
    endpoints implementing connection tests. (CVE-2020-2255)

    * kubernetes: Docker config secrets leaked when file is malformed and loglevel >= 4 (CVE-2020-8564)

    * golang.org/x/text: possibility to trigger an infinite loop in encoding/unicode could lead to crash
    (CVE-2020-14040)

    * podman: environment variables leak between containers when started via Varlink or Docker-compatible REST
    API (CVE-2020-14370)

    * golang: ReadUvarint and ReadVarint can read an unlimited number of bytes from invalid inputs
    (CVE-2020-16845)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_4297.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd86a250");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1819663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1853652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1867099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1874268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1880454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1880456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1880460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1886637");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL OpenShift Container Platform 4.6.1 package based on the guidance in RHSA-2020:4297.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16541");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 117, 212, 297, 362, 522, 835, 862);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-2-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-tests");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/ppc64le/rhocp/4.6/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.6/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.6/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.6/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.6/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.6/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.6/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.6/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'containers-common-1.1.1-2.rhaos4.6.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040']},
      {'reference':'containers-common-1.1.1-2.rhaos4.6.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040']},
      {'reference':'containers-common-1.1.1-2.rhaos4.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040']},
      {'reference':'jenkins-2-plugins-4.6.1601368321-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2019-16541', 'CVE-2020-2252', 'CVE-2020-2254', 'CVE-2020-2255']},
      {'reference':'openshift-clients-4.6.0-202010081244.p0.git.3794.4743d24.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-8564', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'openshift-clients-4.6.0-202010081244.p0.git.3794.4743d24.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-8564', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'openshift-clients-4.6.0-202010081244.p0.git.3794.4743d24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-8564', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'openshift-clients-redistributable-4.6.0-202010081244.p0.git.3794.4743d24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-8564', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'podman-1.9.3-3.rhaos4.6.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040', 'CVE-2020-14370', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'podman-1.9.3-3.rhaos4.6.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040', 'CVE-2020-14370', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'podman-1.9.3-3.rhaos4.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040', 'CVE-2020-14370', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'podman-docker-1.9.3-3.rhaos4.6.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040', 'CVE-2020-14370', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'podman-remote-1.9.3-3.rhaos4.6.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040', 'CVE-2020-14370', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'podman-remote-1.9.3-3.rhaos4.6.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040', 'CVE-2020-14370', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'podman-remote-1.9.3-3.rhaos4.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040', 'CVE-2020-14370', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'podman-tests-1.9.3-3.rhaos4.6.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040', 'CVE-2020-14370', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'podman-tests-1.9.3-3.rhaos4.6.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040', 'CVE-2020-14370', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'podman-tests-1.9.3-3.rhaos4.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040', 'CVE-2020-14370', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'runc-1.0.0-81.rhaos4.6.git5b757d4.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-16845']},
      {'reference':'runc-1.0.0-81.rhaos4.6.git5b757d4.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-16845']},
      {'reference':'runc-1.0.0-81.rhaos4.6.git5b757d4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-16845']},
      {'reference':'skopeo-1.1.1-2.rhaos4.6.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040']},
      {'reference':'skopeo-1.1.1-2.rhaos4.6.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040']},
      {'reference':'skopeo-1.1.1-2.rhaos4.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040']},
      {'reference':'skopeo-tests-1.1.1-2.rhaos4.6.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040']},
      {'reference':'skopeo-tests-1.1.1-2.rhaos4.6.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040']},
      {'reference':'skopeo-tests-1.1.1-2.rhaos4.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-14040']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.6/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.6/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.6/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.6/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.6/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.6/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.6/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.6/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openshift-clients-4.6.0-202010081244.p0.git.3794.4743d24.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-8564', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'openshift-clients-redistributable-4.6.0-202010081244.p0.git.3794.4743d24.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-8564', 'CVE-2020-15586', 'CVE-2020-16845']},
      {'reference':'runc-1.0.0-81.rhaos4.6.git5b757d4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2020-16845']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'containers-common / jenkins-2-plugins / openshift-clients / etc');
}
