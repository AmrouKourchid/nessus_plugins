#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:4829. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155755);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2021-3917",
    "CVE-2021-21685",
    "CVE-2021-21686",
    "CVE-2021-21687",
    "CVE-2021-21688",
    "CVE-2021-21689",
    "CVE-2021-21690",
    "CVE-2021-21691",
    "CVE-2021-21692",
    "CVE-2021-21693",
    "CVE-2021-21694",
    "CVE-2021-21695",
    "CVE-2021-21696",
    "CVE-2021-21697",
    "CVE-2021-21698"
  );
  script_xref(name:"RHSA", value:"2021:4829");
  script_xref(name:"IAVA", value:"2021-A-0551-S");

  script_name(english:"RHEL 8 : OpenShift Container Platform 4.8.22 (RHSA-2021:4829)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for OpenShift Container Platform 4.8.22.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:4829 advisory.

    Red Hat OpenShift Container Platform is Red Hat's cloud computing Kubernetes application platform solution
    designed for on-premise or private cloud deployments.

    This advisory contains the RPM packages for Red Hat OpenShift Container Platform 4.8.22. See the following
    advisory for the container images for this release:

    https://access.redhat.com/errata/RHBA-2021:4830

    All OpenShift Container Platform 4.8 users are advised to upgrade to these updated packages and images
    when they are available in the appropriate release channel. To check for available updates, use the
    OpenShift Console
    or the CLI oc command. Instructions for upgrading a cluster are available at
    https://docs.openshift.com/container-platform/4.8/updating/updating-cluster-between-
    minor.html#understanding-upgrade-channels_updating-cluster-between-minor

    Security Fix(es):

    * jenkins-2-plugins/subversion: does not restrict the name of a file when looking up a subversion key
    (CVE-2021-21698)
    * jenkins: FilePath#mkdirs does not check permission to create parent directories (CVE-2021-21685)
    * jenkins: File path filters do not canonicalize paths, allowing operations to follow symbolic links to
    outside allowed directories (CVE-2021-21686)
    * jenkins: FilePath#untar does not check permission to create symbolic links when unarchiving a symbolic
    link (CVE-2021-21687)
    * jenkins: FilePath#reading(FileVisitor) does not reject any operations allowing users to have
    unrestricted read access (CVE-2021-21688)
    * coreos-installer: restrict access permissions on /boot/ignition{,/config.ign} (CVE-2021-3917)
    * jenkins: FilePath#unzip and FilePath#untar were not subject to any access control (CVE-2021-21689)
    * jenkins: Agent processes are able to completely bypass file path filtering by wrapping the file
    operation in an agent file path (CVE-2021-21690)
    * jenkins: Creating symbolic links is possible without the symlink permission (CVE-2021-21691)
    * jenkins: The operations FilePath#renameTo and FilePath#moveAllChildrenTo only check read permission on
    the source path (CVE-2021-21692)
    * jenkins: When creating temporary files, permission to create files is only checked after theyve been
    created. (CVE-2021-21693)
    * jenkins: FilePath#toURI, FilePath#hasSymlink, FilePath#absolutize, FilePath#isDescendant, and
    FilePath#get*DiskSpace do not check any permissions (CVE-2021-21694)
    * jenkins: FilePath#listFiles lists files outside directories with agent read access when following
    symbolic links. (CVE-2021-21695)
    * jenkins: Agent-to-controller access control allowed writing to sensitive directory used by Pipeline:
    Shared Groovy Libraries Plugin (CVE-2021-21696)
    * jenkins: Agent-to-controller access control allows reading/writing most content of build directories
    (CVE-2021-21697)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_4829.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9c86069");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:4829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2018478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2020385");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL OpenShift Container Platform 4.8.22 package based on the guidance in RHSA-2021:4829.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 59, 276, 281, 863);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:coreos-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-2-plugins");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

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
      {'reference':'coreos-installer-0.9.0-8.rhaos4.8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-3917']},
      {'reference':'coreos-installer-0.9.0-8.rhaos4.8.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-3917']},
      {'reference':'coreos-installer-0.9.0-8.rhaos4.8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-3917']},
      {'reference':'jenkins-2-plugins-4.8.1637599935-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-21698']},
      {'reference':'jenkins-2.303.3.1637596565-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2021-21685', 'CVE-2021-21686', 'CVE-2021-21687', 'CVE-2021-21688', 'CVE-2021-21689', 'CVE-2021-21690', 'CVE-2021-21691', 'CVE-2021-21692', 'CVE-2021-21693', 'CVE-2021-21694', 'CVE-2021-21695', 'CVE-2021-21696', 'CVE-2021-21697']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'coreos-installer / jenkins / jenkins-2-plugins');
}
