#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:2984. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152440);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2021-31525",
    "CVE-2021-33195",
    "CVE-2021-33196",
    "CVE-2021-33197",
    "CVE-2021-33198",
    "CVE-2021-34558"
  );
  script_xref(name:"RHSA", value:"2021:2984");
  script_xref(name:"IAVB", value:"2021-B-0047-S");

  script_name(english:"RHEL 7 / 8 : OpenShift Container Platform 4.8.4 (RHSA-2021:2984)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for OpenShift Container Platform 4.8.4.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:2984 advisory.

    Red Hat OpenShift Container Platform is Red Hat's cloud computing
    Kubernetes application platform solution designed for on-premise or private
    cloud deployments.

    This advisory contains the RPM packages for Red Hat OpenShift Container Platform 4.8.4. See the following
    advisory for the container images for this release:

    https://access.redhat.com/errata/RHSA-2021:2983

    Security Fix(es):

    * golang: net/http: panic in ReadRequest and ReadResponse when reading a very large header
    (CVE-2021-31525)

    * golang: net: lookup functions may return invalid host names (CVE-2021-33195)

    * golang: archive/zip: Malformed archive may cause panic or memory exhaustion (CVE-2021-33196)

    * golang: net/http/httputil: ReverseProxy forwards connection headers if first one is empty
    (CVE-2021-33197)

    * golang: math/big.Rat: may cause a panic or an unrecoverable fatal error if passed inputs with very large
    exponents (CVE-2021-33198)

    * golang: crypto/tls: certificate of wrong type is causing TLS client to panic (CVE-2021-34558)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    All OpenShift Container Platform 4.8 users are advised to upgrade to these updated packages and images
    when they are available in the appropriate release channel. To check for available updates, use the
    OpenShift Console or the CLI oc command. Instructions for upgrading a cluster are available at
    https://docs.openshift.com/container-platform/4.8/updating/updating-cluster-between-
    minor.html#understanding-upgrade-channels_updating-cluster-between-minor

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_2984.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64d6e4cd");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:2984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1958341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1965503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1983596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1988945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1989564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1989570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1989575");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL OpenShift Container Platform 4.8.4 package based on the guidance in RHSA-2021:2984.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 120, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition-validate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/layered/rhel8/ppc64le/rhocp/4.8/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.8/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.8/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.8/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.8/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.8/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.8/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.8/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.8/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'cri-o-1.21.2-8.rhaos4.8.git8d4264e.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33196', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'cri-o-1.21.2-8.rhaos4.8.git8d4264e.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33196', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'cri-o-1.21.2-8.rhaos4.8.git8d4264e.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33196', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'ignition-2.9.0-7.rhaos4.8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'ignition-2.9.0-7.rhaos4.8.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'ignition-2.9.0-7.rhaos4.8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'ignition-validate-2.9.0-7.rhaos4.8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'ignition-validate-2.9.0-7.rhaos4.8.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'ignition-validate-2.9.0-7.rhaos4.8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'openshift-clients-4.8.0-202107292313.p0.git.1077b05.assembly.stream.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33196', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'openshift-clients-4.8.0-202107292313.p0.git.1077b05.assembly.stream.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33196', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'openshift-clients-4.8.0-202107292313.p0.git.1077b05.assembly.stream.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33196', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'openshift-clients-redistributable-4.8.0-202107292313.p0.git.1077b05.assembly.stream.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33196', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'openshift-hyperkube-4.8.0-202107300027.p0.git.38b3ecc.assembly.stream.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'openshift-hyperkube-4.8.0-202107300027.p0.git.38b3ecc.assembly.stream.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'openshift-hyperkube-4.8.0-202107300027.p0.git.38b3ecc.assembly.stream.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.8/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.8/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.8/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.8/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.8/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.8/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.8/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.8/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.8/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'cri-o-1.21.2-8.rhaos4.8.git8d4264e.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33196', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'openshift-clients-4.8.0-202107292313.p0.git.1077b05.assembly.stream.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33196', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'openshift-clients-redistributable-4.8.0-202107292313.p0.git.1077b05.assembly.stream.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33196', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']},
      {'reference':'openshift-hyperkube-4.8.0-202107300027.p0.git.38b3ecc.assembly.stream.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-31525', 'CVE-2021-33195', 'CVE-2021-33197', 'CVE-2021-33198', 'CVE-2021-34558']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cri-o / ignition / ignition-validate / openshift-clients / etc');
}
