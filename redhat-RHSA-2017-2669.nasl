#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2669. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(103046);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2015-8839",
    "CVE-2016-10088",
    "CVE-2016-10741",
    "CVE-2016-7042",
    "CVE-2016-7097",
    "CVE-2016-8645",
    "CVE-2016-9576",
    "CVE-2016-9604",
    "CVE-2016-9685",
    "CVE-2016-9806",
    "CVE-2017-2671",
    "CVE-2017-5551",
    "CVE-2017-5970",
    "CVE-2017-6001",
    "CVE-2017-6951",
    "CVE-2017-7187",
    "CVE-2017-7495",
    "CVE-2017-7533",
    "CVE-2017-7889",
    "CVE-2017-8797",
    "CVE-2017-8890",
    "CVE-2017-9074",
    "CVE-2017-9075",
    "CVE-2017-9076",
    "CVE-2017-9077"
  );
  script_xref(name:"RHSA", value:"2017:2669");

  script_name(english:"RHEL 6 : kernel-rt (RHSA-2017:2669)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel-rt.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2017:2669 advisory.

    The kernel-rt packages provide the Real Time Linux Kernel, which enables fine-tuning for systems with
    extremely high determinism requirements.

    Security Fix(es):

    * A race condition was found in the Linux kernel, present since v3.14-rc1 through v4.12. The race happens
    between threads of inotify_handle_event() and vfs_rename() while running the rename operation against the
    same file. As a result of the race the next slab data or the slab's free list pointer can be corrupted
    with attacker-controlled data, which may lead to the privilege escalation. (CVE-2017-7533, Important)

    * It was found that the NFSv4 server in the Linux kernel did not properly validate layout type when
    processing NFSv4 pNFS LAYOUTGET and GETDEVICEINFO operands. A remote attacker could use this flaw to soft-
    lockup the system and thus cause denial of service. (CVE-2017-8797, Important)

    This update also fixes multiple Moderate and Low impact security issues:

    CVE-2017-8797 CVE-2015-8839 CVE-2016-9576 CVE-2016-7042 CVE-2016-7097 CVE-2016-8645 CVE-2016-9576
    CVE-2016-9806 CVE-2016-10088 CVE-2017-2671 CVE-2017-5970 CVE-2017-6001 CVE-2017-6951 CVE-2017-7187
    CVE-2017-7889 CVE-2017-8890 CVE-2017-9074 CVE-2017-8890 CVE-2017-9075 CVE-2017-8890 CVE-2017-9076
    CVE-2017-8890 CVE-2017-9077 CVE-2016-9604 CVE-2016-9685

    Documentation for these issues are available from the Technical Notes document linked to in the References
    section.

    Red Hat would like to thank Leilei Lin (Alibaba Group), Fan Wu (The University of Hong Kong), and Shixiong
    Zhao (The University of Hong Kong) for reporting CVE-2017-7533 and Marco Grassi for reporting
    CVE-2016-8645. The CVE-2016-7042 issue was discovered by Ondrej Kozina (Red Hat); the CVE-2016-7097 issue
    was discovered by Andreas Gruenbacher (Red Hat) and Jan Kara (SUSE); the CVE-2016-9604 issue was
    discovered by David Howells (Red Hat); and the CVE-2016-9685 issue was discovered by Qian Cai (Red Hat).

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2017/rhsa-2017_2669.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55e6d498");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/3173821");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:2669");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1323577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1368938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1373966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1389433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1393904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1396941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1401502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1403145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1412210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1421638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1422825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1433252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1434327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1436649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1444493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1450972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1452679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1452688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1452691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1452744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1466329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1468283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1479016");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel-rt package based on the guidance in RHSA-2017:2669.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6001");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-9077");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(121, 125, 20, 287, 362, 369, 391, 416, 476, 617, 642, 665, 732, 772);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2015-8839', 'CVE-2016-7042', 'CVE-2016-7097', 'CVE-2016-8645', 'CVE-2016-9576', 'CVE-2016-9604', 'CVE-2016-9685', 'CVE-2016-9806', 'CVE-2016-10088', 'CVE-2016-10741', 'CVE-2017-2671', 'CVE-2017-5551', 'CVE-2017-5970', 'CVE-2017-6001', 'CVE-2017-6951', 'CVE-2017-7187', 'CVE-2017-7495', 'CVE-2017-7533', 'CVE-2017-7889', 'CVE-2017-8797', 'CVE-2017-8890', 'CVE-2017-9074', 'CVE-2017-9075', 'CVE-2017-9076', 'CVE-2017-9077');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2017:2669');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g-execute/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g-execute/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g-execute/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-m/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-m/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-m/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-mgmt/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-mgmt/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-mgmt/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-r/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-r/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-r/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-3.10.0-693.2.1.rt56.585.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-debug-3.10.0-693.2.1.rt56.585.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-debug-devel-3.10.0-693.2.1.rt56.585.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-devel-3.10.0-693.2.1.rt56.585.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-doc-3.10.0-693.2.1.rt56.585.el6rt', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-firmware-3.10.0-693.2.1.rt56.585.el6rt', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-trace-3.10.0-693.2.1.rt56.585.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-trace-devel-3.10.0-693.2.1.rt56.585.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-vanilla-3.10.0-693.2.1.rt56.585.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-vanilla-devel-3.10.0-693.2.1.rt56.585.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-debug / kernel-rt-debug-devel / etc');
}
