#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3322. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104950);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id("CVE-2017-1000380");
  script_xref(name:"RHSA", value:"2017:3322");

  script_name(english:"RHEL 7 : kernel-rt (RHSA-2017:3322)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2017:3322 advisory.

    The kernel-rt packages provide the Real Time Linux Kernel, which enables fine-tuning for systems with
    extremely high determinism requirements.

    Security Fix(es):

    * It was found that the timer functionality in the Linux kernel ALSA subsystem is prone to a race
    condition between read and ioctl system call handlers, resulting in an uninitialized memory disclosure to
    user space. A local user could use this flaw to read information belonging to other users.
    (CVE-2017-1000380, Moderate)

    Red Hat would like to thank Alexander Potapenko (Google) for reporting this issue.

    Bug Fix(es):

    * The kernel-rt packages have been upgraded to the 3.10.0-693.11.1 source tree, which provides a number of
    bug fixes over the previous version. (BZ#1500035)

    * Previously, the hfi1 driver called the preempt_disable() function to prevent migration on standard Red
    Hat Enterprise Linux and on Red Hat Enterprise Linux for Real Time. On Red Hat Enterprise Linux for Real
    Time with the realtime kernel (kernel-rt), calling preempt_disable() triggered a kernel panic. With this
    update, the kernel-rt code has been modified to use a realtime-specific function call to the
    preempt_disable_nort() function, which expands to the correct calls based on the kernel that is running.
    As a result, the hfi1 driver now works correctly on both Red Hat Enterprise Linux kernel and Red Hat
    Enterprise Linux for Real Time kernel-rt. (BZ#1507053)

    * Previously, the hfi1 driver called the preempt_disable() function to prevent migration on standard Red
    Hat Enterprise Linux and on Red Hat Enterprise Linux for Real Time. On Red Hat Enterprise Linux for Real
    Time with the realtime kernel (kernel-rt), calling preempt_disable() triggered a kernel panic. With this
    update, the kernel-rt code has been modified to use a realtime-specific function call to the
    preempt_disable_nort() function, which expands to the correct calls based on the kernel that is running.
    As a result, the hfi1 driver now works correctly on both Red Hat Enterprise Linux kernel and Red Hat
    Enterprise Linux for Real Time kernel-rt. (BZ#1507054)

    * In the realtime kernel, if the rt_mutex locking mechanism was taken in the interrupt context, the normal
    priority inheritance protocol incorrectly identified a deadlock, and a kernel panic occurred. This update
    reverts the patch that added rt_mutex in the interrupt context, and the kernel no longer panics due to
    this behavior. (BZ#1511382)

    Enhancement(s):

    * The current realtime throttling mechanism prevents the starvation of non-realtime tasks by CPU-intensive
    realtime tasks. When a realtime run queue is throttled, it allows non-realtime tasks to run. If there are
    not non-realtime tasks, the CPU goes idle. To safely maximize CPU usage by decreasing the CPU idle time,
    the RT_RUNTIME_GREED scheduler feature has been implemented. When enabled, this feature checks if non-
    realtime tasks are starving before throttling the realtime task. The RT_RUNTIME_GREED scheduler option
    guarantees some run time on all CPUs for the non-realtime tasks, while keeping the realtime tasks running
    as much as possible. (BZ#1505158)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2017/rhsa-2017_3322.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fe3691a");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:3322");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1463311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1500035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1505158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1507054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1511382");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000380");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list('CVE-2017-1000380');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2017:3322');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7.9/x86_64/nfv/debug',
      'content/dist/rhel/server/7/7.9/x86_64/nfv/os',
      'content/dist/rhel/server/7/7.9/x86_64/nfv/source/SRPMS',
      'content/dist/rhel/server/7/7.9/x86_64/rt/debug',
      'content/dist/rhel/server/7/7.9/x86_64/rt/os',
      'content/dist/rhel/server/7/7.9/x86_64/rt/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/debug',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/os',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rt/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rt/os',
      'content/dist/rhel/server/7/7Server/x86_64/rt/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/rt/debug',
      'content/els/rhel/server/7/7Server/x86_64/rt/os',
      'content/els/rhel/server/7/7Server/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-3.10.0-693.11.1.rt56.632.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-3.10.0-693.11.1.rt56.632.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-3.10.0-693.11.1.rt56.632.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-3.10.0-693.11.1.rt56.632.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-3.10.0-693.11.1.rt56.632.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-doc-3.10.0-693.11.1.rt56.632.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-3.10.0-693.11.1.rt56.632.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-trace-3.10.0-693.11.1.rt56.632.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-trace-devel-3.10.0-693.11.1.rt56.632.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-trace-kvm-3.10.0-693.11.1.rt56.632.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
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
