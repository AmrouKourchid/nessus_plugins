#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:1677. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174389);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2022-23521",
    "CVE-2022-41903",
    "CVE-2023-0266",
    "CVE-2023-0386",
    "CVE-2023-0767"
  );
  script_xref(name:"RHSA", value:"2023:1677");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"RHEL 8 : Red Hat Virtualization Host 4.4.z SP 1 security update batch#5 (oVirt-4.5.3-5) (Important) (RHSA-2023:1677)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat Virtualization Host 4.4.z SP 1.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2023:1677 advisory.

    The redhat-virtualization-host packages provide the Red Hat Virtualization Host. These packages include
    redhat-release-virtualization-host, ovirt-node, and rhev-hypervisor. Red Hat Virtualization Hosts (RHVH)
    are installed using a special build of Red Hat Enterprise Linux with only the packages required to host
    virtual machines. RHVH features a Cockpit user interface for monitoring the host's resources and
    performing administrative tasks.

    The ovirt-node-ng packages provide the Red Hat Virtualization Host. These packages include redhat-release-
    virtualization-host, ovirt-node, and rhev-hypervisor. Red Hat Virtualization Hosts (RHVH) are installed
    using a special build of Red Hat Enterprise Linux with only the packages required to host virtual
    machines. RHVH features a Cockpit user interface for monitoring the host's resources and performing
    administrative tasks.

    Security Fix(es):

    * git: gitattributes parsing integer overflow (CVE-2022-23521)

    * git: Heap overflow in `git archive`, `git log --format` leading to RCE (CVE-2022-41903)

    * ALSA: pcm: Move rwsem lock inside snd_ctl_elem_read to prevent UAF (CVE-2023-0266)

    * kernel: FUSE filesystem low-privileged user privileges escalation (CVE-2023-0386)

    * nss: Arbitrary memory write via PKCS 12 (CVE-2023-0767)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_1677.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25afce7b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:1677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2159505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2170377");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat Virtualization Host 4.4.z SP 1 package based on the guidance in RHSA-2023:1677.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0767");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-41903");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Local Privilege Escalation via CVE-2023-0386');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119, 190, 282, 416);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-virtualization-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-virtualization-host-image-update");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/layered/rhel8/x86_64/rhv-mgmt-agent/4/debug',
      'content/dist/layered/rhel8/x86_64/rhv-mgmt-agent/4/os',
      'content/dist/layered/rhel8/x86_64/rhv-mgmt-agent/4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhv-tools/4/debug',
      'content/dist/layered/rhel8/x86_64/rhv-tools/4/os',
      'content/dist/layered/rhel8/x86_64/rhv-tools/4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhvh-build/4/debug',
      'content/dist/layered/rhel8/x86_64/rhvh-build/4/os',
      'content/dist/layered/rhel8/x86_64/rhvh-build/4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhvh/4/debug',
      'content/dist/layered/rhel8/x86_64/rhvh/4/os',
      'content/dist/layered/rhel8/x86_64/rhvh/4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'redhat-virtualization-host-image-update-4.5.3-202304051438_8.6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'redhat-virtualization-host-image-update');
}
