#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1374. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109831);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id("CVE-2017-5754", "CVE-2018-1000199");
  script_xref(name:"RHSA", value:"2018:1374");

  script_name(english:"RHEL 7 : kernel-alt (RHSA-2018:1374)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel-alt.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2018:1374 advisory.

    The kernel-alt packages provide the Linux kernel version 4.x.

    Security Fix(es):

    * kernel: ptrace() incorrect error handling leads to corruption and DoS (CVE-2018-1000199)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

    Red Hat would like to thank Andy Lutomirski for reporting this issue.

    Bug Fix(es):

    * Previously, the nfs_commit_inode() function did not respect the FLUSH_SYNC argument and exited even if
    there were already the in-flight COMMIT requests. As a consequence, the mmap() system call occasionally
    returned the EBUSY error on NFS, and CPU soft lockups occurred during a writeback on NFS. This update
    fixes nfs_commit_inode() to respect FLUSH_SYNC. As a result, mmap() does not return EBUSY, and the CPU
    soft lockups no longer occur during NFS writebacks. (BZ#1559869)

    * Recent IBM z Systems hardware contains an extension to the time-of-day clock that ensures it will be
    operational after the year 2042 by avoiding an overflow that would happen without it. However, the KVM
    hypervisor was previously unable to handle the extension correctly, which lead to guests freezing if their
    kernel supported the time-of-day clock extension. This update adds support for the extension to the KVM
    hypervisor, and KVM guests which support it no longer freeze. (BZ#1559871)

    * This update provides the ability to disable the RFI Flush mitigation mechanism for the Meltdown
    vulnerability (CVE-2017-5754) in the kernel. The patches that mitigate the effect of Meltdown may have
    negative impact on performance when the mechanism they provide is enabled, and at the same time your
    systems may not need this mitigation if they are secured by other means. The vulnerability mitigation
    remains enabled by default and must be disabled manually; this restores system performance to original
    levels, but the system then also remains vulnerable to Meltdown. Instructions describing how to disable
    RFI Flush, as well as additional information, is provided in the following Red Hat Knowledgebase article:
    https://access.redhat.com/articles/3311301 (BZ#1561463)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2018/rhsa-2018_1374.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c253d24a");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/3311301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568477");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:1374");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-1000199");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel-alt package based on the guidance in RHSA-2018:1374.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5754");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(200, 460);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-alt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2017-5754', 'CVE-2018-1000199');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2018:1374');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/debug',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/optional/os',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/os',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/source/SRPMS',
      'content/dist/rhel/power-le/7/7.9/ppc64le/debug',
      'content/dist/rhel/power-le/7/7.9/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7.9/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7.9/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7.9/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7.9/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7.9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7.9/ppc64le/os',
      'content/dist/rhel/power-le/7/7.9/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7.9/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7.9/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7.9/ppc64le/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/dist/rhel/power/7/7.9/ppc64/debug',
      'content/dist/rhel/power/7/7.9/ppc64/optional/debug',
      'content/dist/rhel/power/7/7.9/ppc64/optional/os',
      'content/dist/rhel/power/7/7.9/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7.9/ppc64/os',
      'content/dist/rhel/power/7/7.9/ppc64/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/os',
      'content/dist/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/os',
      'content/dist/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/dist/rhel/system-z/7/7.9/s390x/debug',
      'content/dist/rhel/system-z/7/7.9/s390x/highavailability/debug',
      'content/dist/rhel/system-z/7/7.9/s390x/highavailability/os',
      'content/dist/rhel/system-z/7/7.9/s390x/highavailability/source/SRPMS',
      'content/dist/rhel/system-z/7/7.9/s390x/optional/debug',
      'content/dist/rhel/system-z/7/7.9/s390x/optional/os',
      'content/dist/rhel/system-z/7/7.9/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/7/7.9/s390x/os',
      'content/dist/rhel/system-z/7/7.9/s390x/resilientstorage/debug',
      'content/dist/rhel/system-z/7/7.9/s390x/resilientstorage/os',
      'content/dist/rhel/system-z/7/7.9/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel/system-z/7/7.9/s390x/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/os',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/os',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/os',
      'content/fastrack/rhel/power/7/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/os',
      'content/fastrack/rhel/power/7/ppc64/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/os',
      'content/fastrack/rhel/system-z/7/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/os',
      'content/fastrack/rhel/system-z/7/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-4.14.0-49.2.2.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.14.0-49.2.2.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.14.0-49.2.2.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-4.14.0-49.2.2.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.14.0-49.2.2.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.14.0-49.2.2.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.14.0-49.2.2.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.14.0-49.2.2.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.14.0-49.2.2.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.14.0-49.2.2.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.14.0-49.2.2.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.14.0-49.2.2.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.14.0-49.2.2.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.14.0-49.2.2.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.14.0-49.2.2.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.14.0-49.2.2.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-4.14.0-49.2.2.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-4.14.0-49.2.2.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.14.0-49.2.2.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.14.0-49.2.2.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.14.0-49.2.2.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.14.0-49.2.2.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.14.0-49.2.2.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.14.0-49.2.2.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.14.0-49.2.2.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.14.0-49.2.2.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.14.0-49.2.2.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-4.14.0-49.2.2.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-4.14.0-49.2.2.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-4.14.0-49.2.2.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-bootwrapper / kernel-debug / kernel-debug-devel / etc');
}
