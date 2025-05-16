#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0103. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(88558);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2015-8104", "CVE-2016-0728", "CVE-2016-0774");
  script_xref(name:"RHSA", value:"2016:0103");

  script_name(english:"RHEL 7 : kernel (RHSA-2016:0103)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2016:0103 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux
    operating system.

    * It was found that the x86 ISA (Instruction Set Architecture) is prone to
    a denial of service attack inside a virtualized environment in the form of
    an infinite loop in the microcode due to the way (sequential) delivering of
    benign exceptions such as #DB (debug exception) is handled. A privileged
    user inside a guest could use this flaw to create denial of service
    conditions on the host kernel. (CVE-2015-8104, Important)

    * A use-after-free flaw was found in the way the Linux kernel's key
    management subsystem handled keyring object reference counting in certain
    error path of the join_session_keyring() function. A local, unprivileged
    user could use this flaw to escalate their privileges on the system.
    (CVE-2016-0728, Important)

    * It was found that the fix for CVE-2015-1805 incorrectly kept buffer
    offset and buffer length in sync on a failed atomic read, potentially
    resulting in a pipe buffer state corruption. A local, unprivileged user
    could use this flaw to crash the system or leak kernel memory to user
    space. (CVE-2016-0774, Moderate)

    Red Hat would like to thank the Perception Point research team for
    reporting the CVE-2016-0728 issue. The security impact of the CVE-2016-0774
    issue was discovered by Red Hat.

    Bug fixes:

    * NMI watchdog of guests using legacy LVT0-based NMI delivery did not work
    with APICv. Now, NMI works with LVT0 regardless of APICv. (BZ#1244726)

    * Parallel file-extending direct I/O writes could previously race to update
    the size of the file. If they executed out-of-order, the file size could
    move backwards and push a previously completed write beyond the end of the
    file, causing it to be lost. (BZ#1258942)

    * The GHES NMI handler had a global spin lock that significantly increased
    the latency of each perf sample collection. This update simplifies locking
    inside the handler. (BZ#1280200)

    * Sometimes, iptables rules are updated along with ip rules, and routes are
    reloaded. Previously, skb->sk was mistakenly attached to some IPv6
    forwarding traffic packets, which could cause kernel panic. Now, such
    packets are checked and not processed. (BZ#1281700)

    * The NUMA node was not reported for PCI adapters, which affected every
    POWER system deployed with Red Hat Enterprise Linux 7 and caused
    significant decrease in the system performance. (BZ#1283525)

    * Processing packets with a lot of different IPv6 source addresses caused
    the kernel to return warnings concerning soft-lockups due to high lock
    contention and latency increase. (BZ#1285369)

    * Running edge triggered interrupts with an ack notifier when
    simultaneously reconfiguring the Intel I/O IOAPIC did not work correctly,
    so EOI in the interrupt did not cause a VM to exit if APICv was enabled.
    Consequently, the VM sometimes became unresponsive. (BZ#1287001)

    * Block device readahead was artificially limited, so the read performance
    was poor, especially on RAID devices. Now, per-device readahead limits are
    used for each device, which has improved read performance. (BZ#1287548)

    * Identical expectations could not be tracked simultaneously even if they
    resided in different connection tracking zones. Now, an expectation insert
    attempt is rejected only if the zone is also identical. (BZ#1290093)

    * The storvsc kernel driver for Microsoft Hyper-V storage was setting
    incorrect SRB flags, and Red Hat Enterprise Linux 7 guests running on
    Microsoft Hyper-V were experiencing slow I/O as well as I/O failures when
    they were connected to a virtual SAN. Now, SRB flags are set correctly.
    (BZ#1290095)

    * When a NUMA system with no memory in node 0 was used, the system
    terminated unexpectedly during boot or when using OpenVSwitch. Now, the
    kernel tries to allocate memory from other nodes when node 0 is not
    present. (BZ#1300950)

    Enhancement:

    * IPsec has been updated to provide many fixes and some enhancements.
    Of particular note is the ability to match on outgoing interfaces.
    (BZ#1287407)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2016/rhsa-2016_0103.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4203108f");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:0103");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1278496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1297475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1303961");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0728");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(416, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/03");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:7.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '7.1')) audit(AUDIT_OS_NOT, 'Red Hat 7.1', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2015-8104', 'CVE-2016-0728', 'CVE-2016-0774');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2016:0103');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/eus/rhel/computenode/7/7.1/x86_64/debug',
      'content/eus/rhel/computenode/7/7.1/x86_64/optional/debug',
      'content/eus/rhel/computenode/7/7.1/x86_64/optional/os',
      'content/eus/rhel/computenode/7/7.1/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/7/7.1/x86_64/os',
      'content/eus/rhel/computenode/7/7.1/x86_64/source/SRPMS',
      'content/eus/rhel/power-le/7/7.1/ppc64le/debug',
      'content/eus/rhel/power-le/7/7.1/ppc64le/optional/debug',
      'content/eus/rhel/power-le/7/7.1/ppc64le/optional/os',
      'content/eus/rhel/power-le/7/7.1/ppc64le/optional/source/SRPMS',
      'content/eus/rhel/power-le/7/7.1/ppc64le/os',
      'content/eus/rhel/power-le/7/7.1/ppc64le/source/SRPMS',
      'content/eus/rhel/power/7/7.1/ppc64/debug',
      'content/eus/rhel/power/7/7.1/ppc64/optional/debug',
      'content/eus/rhel/power/7/7.1/ppc64/optional/os',
      'content/eus/rhel/power/7/7.1/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/7/7.1/ppc64/os',
      'content/eus/rhel/power/7/7.1/ppc64/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/debug',
      'content/eus/rhel/server/7/7.1/x86_64/highavailability/debug',
      'content/eus/rhel/server/7/7.1/x86_64/highavailability/os',
      'content/eus/rhel/server/7/7.1/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/optional/debug',
      'content/eus/rhel/server/7/7.1/x86_64/optional/os',
      'content/eus/rhel/server/7/7.1/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/os',
      'content/eus/rhel/server/7/7.1/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/7/7.1/x86_64/resilientstorage/os',
      'content/eus/rhel/server/7/7.1/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/7/7.1/s390x/debug',
      'content/eus/rhel/system-z/7/7.1/s390x/optional/debug',
      'content/eus/rhel/system-z/7/7.1/s390x/optional/os',
      'content/eus/rhel/system-z/7/7.1/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/7/7.1/s390x/os',
      'content/eus/rhel/system-z/7/7.1/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-229.26.2.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/eus/rhel/power-le/7/7.1/ppc64le/debug',
      'content/eus/rhel/power-le/7/7.1/ppc64le/optional/debug',
      'content/eus/rhel/power-le/7/7.1/ppc64le/optional/os',
      'content/eus/rhel/power-le/7/7.1/ppc64le/optional/source/SRPMS',
      'content/eus/rhel/power-le/7/7.1/ppc64le/os',
      'content/eus/rhel/power-le/7/7.1/ppc64le/source/SRPMS',
      'content/eus/rhel/power/7/7.1/ppc64/debug',
      'content/eus/rhel/power/7/7.1/ppc64/optional/debug',
      'content/eus/rhel/power/7/7.1/ppc64/optional/os',
      'content/eus/rhel/power/7/7.1/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/7/7.1/ppc64/os',
      'content/eus/rhel/power/7/7.1/ppc64/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/debug',
      'content/eus/rhel/server/7/7.1/x86_64/highavailability/debug',
      'content/eus/rhel/server/7/7.1/x86_64/highavailability/os',
      'content/eus/rhel/server/7/7.1/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/optional/debug',
      'content/eus/rhel/server/7/7.1/x86_64/optional/os',
      'content/eus/rhel/server/7/7.1/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/os',
      'content/eus/rhel/server/7/7.1/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/7/7.1/x86_64/resilientstorage/os',
      'content/eus/rhel/server/7/7.1/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/7/7.1/s390x/debug',
      'content/eus/rhel/system-z/7/7.1/s390x/optional/debug',
      'content/eus/rhel/system-z/7/7.1/s390x/optional/os',
      'content/eus/rhel/system-z/7/7.1/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/7/7.1/s390x/os',
      'content/eus/rhel/system-z/7/7.1/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-3.10.0-229.26.2.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-229.26.2.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-229.26.2.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-229.26.2.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-229.26.2.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-229.26.2.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-229.26.2.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-229.26.2.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-229.26.2.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-229.26.2.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-229.26.2.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
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
