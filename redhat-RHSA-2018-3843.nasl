#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3843. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119758);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id("CVE-2018-14646");
  script_xref(name:"RHSA", value:"2018:3843");

  script_name(english:"RHEL 7 : kernel (RHSA-2018:3843)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2018:3843 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: NULL pointer dereference in af_netlink.c:__netlink_ns_capable() allows for denial of service
    (CVE-2018-14646)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

    Red Hat would like to thank Christian Brauner for reporting this issue.

    Bug Fix(es):

    * Previously, the kernel architectures for IBM z Systems were missing support to display the status of the
    Spectre v2 mitigations. As a consequence, the /sys/devices/system/cpu/vulnerabilities/spectre_v2 file did
    not exist. With this update, the kernel now shows the status in the above mentioned file and as a result,
    the file now reports either Vulnerable or Mitigation: execute trampolines message. (BZ#1636884)

    * Previously, under certain conditions, the page direct reclaim code was occasionally stuck in a loop when
    waiting for the reclaim to finish. As a consequence, affected applications became unresponsive with no
    progress possible. This update fixes the bug by modifying the page direct reclaim code to bound the
    waiting time for the reclaim to finish. As a consequence, the affected applications no longer hang in the
    described scenario. (BZ#1635132)

    * Previously, a packet was missing the User Datagram Protocol (UDP) payload checksum during a full
    checksum computation, if the hardware checksum was not applied. As a consequence, a packet with an
    incorrect checksum was dropped by a peer. With this update, the kernel includes the UDP payload checksum
    during the full checksum computation. As a result, the checksum is computed correctly and the packet can
    be received by the peer. (BZ#1635796)

    * Previously, on user setups running a mixed workload, the scheduler did not pick up tasks because the
    runqueues were throttled for a long time. As a consequence, the system became partially unresponsive. To
    fix this bug, the kernel now sets a flag in the cfs_bandwidth struct to secure better task distribution.
    As a result, the system no longer becomes unresponsive in the described scenario. (BZ#1640676)

    * Previously, clearing a CPU mask with the cgroups feature triggered the following warning:

        kernel: WARNING: CPU: 422 PID: 364940 at kernel/cpuset.c:955 update_cpumasks_hier+0x3af/0x410

    As a consequence, the user's log file was flooded with similar warning messages as above. This update
    fixes the bug and the warning message no longer appears in the described scenario. (BZ#1644237)

    * Previously, a lot of CPU time was occasionally spent in the kernel during a teardown of a container with
    a lot of memory assigned. As a consequence, an increased risk of CPU soft lockups could occur due to
    higher latency of a CPU scheduler for other processes during the container teardown. To fix the problem,
    the kernel now adds a reschedule to the tight kernel loop. As a result, the CPU scheduler latency is not
    increased by the container teardown and there is not the increased risk of CPU soft lockups in the
    described scenario. (BZ#1644672)

    * When a user created a VLAN device, the kernel set the wanted_features set of the VLAN to the current
    features of the base device. As a consequence, when the base device got new features, the features were
    not propagated to the VLAN device. This update fixes the bug and the VLAN device receives the new features
    in the described scenario.

    Note that this only affects TCP Segmentation Offload (TSO). (BZ#1644674)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2018/rhsa-2018_3843.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b0b76b6");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:3843");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1630124");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2018:3843.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14646");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(476);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:7.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '7.5')) audit(AUDIT_OS_NOT, 'Red Hat 7.5', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2018-14646');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2018:3843');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/eus/rhel/computenode/7/7.5/x86_64/debug',
      'content/eus/rhel/computenode/7/7.5/x86_64/optional/debug',
      'content/eus/rhel/computenode/7/7.5/x86_64/optional/os',
      'content/eus/rhel/computenode/7/7.5/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/7/7.5/x86_64/os',
      'content/eus/rhel/computenode/7/7.5/x86_64/source/SRPMS',
      'content/eus/rhel/power-le/7/7.5/ppc64le/debug',
      'content/eus/rhel/power-le/7/7.5/ppc64le/highavailability/debug',
      'content/eus/rhel/power-le/7/7.5/ppc64le/highavailability/os',
      'content/eus/rhel/power-le/7/7.5/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel/power-le/7/7.5/ppc64le/optional/debug',
      'content/eus/rhel/power-le/7/7.5/ppc64le/optional/os',
      'content/eus/rhel/power-le/7/7.5/ppc64le/optional/source/SRPMS',
      'content/eus/rhel/power-le/7/7.5/ppc64le/os',
      'content/eus/rhel/power-le/7/7.5/ppc64le/resilientstorage/debug',
      'content/eus/rhel/power-le/7/7.5/ppc64le/resilientstorage/os',
      'content/eus/rhel/power-le/7/7.5/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel/power-le/7/7.5/ppc64le/source/SRPMS',
      'content/eus/rhel/power/7/7.5/ppc64/debug',
      'content/eus/rhel/power/7/7.5/ppc64/optional/debug',
      'content/eus/rhel/power/7/7.5/ppc64/optional/os',
      'content/eus/rhel/power/7/7.5/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/7/7.5/ppc64/os',
      'content/eus/rhel/power/7/7.5/ppc64/source/SRPMS',
      'content/eus/rhel/server/7/7.5/x86_64/debug',
      'content/eus/rhel/server/7/7.5/x86_64/highavailability/debug',
      'content/eus/rhel/server/7/7.5/x86_64/highavailability/os',
      'content/eus/rhel/server/7/7.5/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/7/7.5/x86_64/optional/debug',
      'content/eus/rhel/server/7/7.5/x86_64/optional/os',
      'content/eus/rhel/server/7/7.5/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/7/7.5/x86_64/os',
      'content/eus/rhel/server/7/7.5/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/7/7.5/x86_64/resilientstorage/os',
      'content/eus/rhel/server/7/7.5/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/7/7.5/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/7/7.5/s390x/debug',
      'content/eus/rhel/system-z/7/7.5/s390x/optional/debug',
      'content/eus/rhel/system-z/7/7.5/s390x/optional/os',
      'content/eus/rhel/system-z/7/7.5/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/7/7.5/s390x/os',
      'content/eus/rhel/system-z/7/7.5/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-862.25.3.el7', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
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
