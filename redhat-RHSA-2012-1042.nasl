#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1042. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64044);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2011-4347",
    "CVE-2012-0038",
    "CVE-2012-0044",
    "CVE-2012-1097",
    "CVE-2012-1179"
  );
  script_bugtraq_id(
    50811,
    51371,
    51380,
    52274,
    52533
  );
  script_xref(name:"RHSA", value:"2012:1042");

  script_name(english:"RHEL 6 : kernel (RHSA-2012:1042)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2012:1042 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux
    operating system.

    This update fixes the following security issues:

    * A local, unprivileged user could use an integer overflow flaw in
    drm_mode_dirtyfb_ioctl() to cause a denial of service or escalate their
    privileges. (CVE-2012-0044, Important)

    * It was found that the kvm_vm_ioctl_assign_device() function in the KVM
    (Kernel-based Virtual Machine) subsystem of a Linux kernel did not check if
    the user requesting device assignment was privileged or not. A local,
    unprivileged user on the host could assign unused PCI devices, or even
    devices that were in use and whose resources were not properly claimed by
    the respective drivers, which could result in the host crashing.
    (CVE-2011-4347, Moderate)

    * A flaw was found in the way the Linux kernel's XFS file system
    implementation handled on-disk Access Control Lists (ACLs). A local,
    unprivileged user could use this flaw to cause a denial of service or
    escalate their privileges by mounting a specially-crafted disk.
    (CVE-2012-0038, Moderate)

    * It was found that the Linux kernel's register set (regset) common
    infrastructure implementation did not check if the required get and set
    handlers were initialized. A local, unprivileged user could use this flaw
    to cause a denial of service by performing a register set operation with a
    ptrace() PTRACE_SETREGSET or PTRACE_GETREGSET request. (CVE-2012-1097,
    Moderate)

    * A race condition was found in the Linux kernel's memory management
    subsystem in the way pmd_none_or_clear_bad(), when called with mmap_sem in
    read mode, and Transparent Huge Pages (THP) page faults interacted. A
    privileged user in a KVM guest with the ballooning functionality enabled
    could potentially use this flaw to crash the host. A local, unprivileged
    user could use this flaw to crash the system. (CVE-2012-1179, Moderate)

    Red Hat would like to thank Chen Haogang for reporting CVE-2012-0044; Sasha
    Levin for reporting CVE-2011-4347; Wang Xi for reporting CVE-2012-0038; and
    H. Peter Anvin for reporting CVE-2012-1097.

    This update also fixes the following bugs:

    * When a RoCE (RDMA over Converged Ethernet) adapter with active RoCE
    communications was taken down suddenly (either by adapter failure or the
    intentional shutdown of the interface), the ongoing RoCE communications
    could cause the kernel to panic and render the machine unusable. A patch
    has been provided to protect the kernel in this situation and to pass an
    error up to the application still using the interface after it has been
    taken down instead. (BZ#799944)

    * The fix for Red Hat Bugzilla bug 713494, released via RHSA-2011:0928,
    introduced a regression. Attempting to change the state of certain
    features, such as GRO (Generic Receive Offload) or TSO (TCP segment
    offloading), for a 10 Gigabit Ethernet card that is being used in a
    virtual LAN (VLAN) resulted in a kernel panic. (BZ#816974)

    * If a new file was created on a Network File System version 4 (NFSv4)
    share, the ownership was set to nfsnobody (-2) until it was possible to
    upcall to the idmapper. As a consequence, subsequent file system operations
    could incorrectly use -2 for the user and group IDs for the given file,
    causing certain operations to fail. In reported cases, this issue also
    caused Viminfo file is not writable errors for users running Vim with
    files on an NFSv4 share. (BZ#820960)

    Users should upgrade to these updated packages, which contain backported
    patches to correct these issues. The system must be rebooted for this
    update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2012/rhsa-2012_1042.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd2cd3f5");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2012:1042");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=756084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=772894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=773280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=799209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=803793");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHSA-2011-0928.html");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2012:1042.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(190);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:6.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '6.1')) audit(AUDIT_OS_NOT, 'Red Hat 6.1', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2011-4347', 'CVE-2012-0038', 'CVE-2012-0044', 'CVE-2012-1097', 'CVE-2012-1179');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2012:1042');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/eus/rhel/power/6/6.1/ppc64/debug',
      'content/eus/rhel/power/6/6.1/ppc64/optional/debug',
      'content/eus/rhel/power/6/6.1/ppc64/optional/os',
      'content/eus/rhel/power/6/6.1/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/6/6.1/ppc64/os',
      'content/eus/rhel/power/6/6.1/ppc64/source/SRPMS',
      'content/eus/rhel/server/6/6.1/i386/debug',
      'content/eus/rhel/server/6/6.1/i386/highavailability/debug',
      'content/eus/rhel/server/6/6.1/i386/highavailability/os',
      'content/eus/rhel/server/6/6.1/i386/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.1/i386/loadbalancer/debug',
      'content/eus/rhel/server/6/6.1/i386/loadbalancer/os',
      'content/eus/rhel/server/6/6.1/i386/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.1/i386/optional/debug',
      'content/eus/rhel/server/6/6.1/i386/optional/os',
      'content/eus/rhel/server/6/6.1/i386/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.1/i386/os',
      'content/eus/rhel/server/6/6.1/i386/resilientstorage/debug',
      'content/eus/rhel/server/6/6.1/i386/resilientstorage/os',
      'content/eus/rhel/server/6/6.1/i386/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.1/i386/source/SRPMS',
      'content/eus/rhel/server/6/6.1/x86_64/debug',
      'content/eus/rhel/server/6/6.1/x86_64/highavailability/debug',
      'content/eus/rhel/server/6/6.1/x86_64/highavailability/os',
      'content/eus/rhel/server/6/6.1/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.1/x86_64/loadbalancer/debug',
      'content/eus/rhel/server/6/6.1/x86_64/loadbalancer/os',
      'content/eus/rhel/server/6/6.1/x86_64/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.1/x86_64/optional/debug',
      'content/eus/rhel/server/6/6.1/x86_64/optional/os',
      'content/eus/rhel/server/6/6.1/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.1/x86_64/os',
      'content/eus/rhel/server/6/6.1/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/6/6.1/x86_64/resilientstorage/os',
      'content/eus/rhel/server/6/6.1/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.1/x86_64/scalablefilesystem/debug',
      'content/eus/rhel/server/6/6.1/x86_64/scalablefilesystem/os',
      'content/eus/rhel/server/6/6.1/x86_64/scalablefilesystem/source/SRPMS',
      'content/eus/rhel/server/6/6.1/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/6/6.1/s390x/debug',
      'content/eus/rhel/system-z/6/6.1/s390x/optional/debug',
      'content/eus/rhel/system-z/6/6.1/s390x/optional/os',
      'content/eus/rhel/system-z/6/6.1/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/6/6.1/s390x/os',
      'content/eus/rhel/system-z/6/6.1/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-firmware-2.6.32-131.29.1.el6', 'sp':'1', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-131.29.1.el6', 'sp':'1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
