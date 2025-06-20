#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1583. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(85341);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2015-3636");
  script_xref(name:"RHSA", value:"2015:1583");

  script_name(english:"RHEL 6 : kernel (RHSA-2015:1583)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2015:1583 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux
    operating system.

    * It was found that the Linux kernel's ping socket implementation did not
    properly handle socket unhashing during spurious disconnects, which could
    lead to a use-after-free flaw. On x86-64 architecture systems, a local user
    able to create ping sockets could use this flaw to crash the system.
    On non-x86-64 architecture systems, a local user able to create ping
    sockets could use this flaw to escalate their privileges on the system.
    (CVE-2015-3636, Moderate)

    This update also fixes the following bugs:

    * Previously, the bridge device did not propagate VLAN information to its
    ports and Generic Receive Offload (GRO) information to devices that sit on
    top. This resulted in lower receive performance of VLANs over bridge
    devices because GRO was not enabled. An attempt to resolve this problem was
    made with BZ#858198 by introducing a patch that allows VLANs to be
    registered with the participating bridge ports and adds GRO to the bridge
    device feature set, however, that attempt introduced a number of
    regressions, which broke the vast majority of stacked setups involving
    bridge devices and VLANs. This update reverts the patch provided by
    BZ#858198 and removes support for this capability. (BZ#1131697)

    * The backlog data could previously not be consumed when the
    audit_log_start() function was running even if audit_log_start() called the
    wait_for_auditd() function to consume it. As only auditd could consume the
    backlog data, audit_log_start() terminated unexpectedly. Consequently, the
    system became unresponsive until the backlog timeout was up again.
    With this update, audit_log_start() no longer terminates and the system
    shuts down and reboots gracefully in a timely manner. (BZ#1140490)

    * This update introduces a set of patches with a new VLAN model to conform
    to upstream standards. In addition, this set of patches fixes other issues
    such as transmission of Internet Control Message Protocol (ICMP) fragments.
    (BZ#1173560)

    * Due to a bug in the audit code, a kernel panic occurred in the
    tasklist_lock variable if SELinux was in permissive or enforcing mode.
    A patch has been applied to fix this bug, and the operating system now
    continues to work normally. (BZ#1236103)

    * If a server returned an empty or malformed READDIR response, the NFS
    client could previously terminate unexpectedly while attempting to decode
    that response. This update uses the response size to determine if existing
    pages of data are available for decoding, and the client only decodes the
    responses if they exist. As a result, the NFS client no longer attempts to
    decode pages of data that may not exist, and the aforementioned crash is
    thus avoided. (BZ#1232133)

    * Previously, if a slave device had a receive handler registered, then an
    error unwind of bonding device enslave function became broken, which led to
    a kernel oops. This update detaches the slave in the unwind path, and the
    aforementioned oops no longer occurs. (BZ#1222482)

    * Due to bad memory or memory corruption, an isolated BUG_ON(mm->nr_ptes)
    was sometimes reported, indicating that not all the page tables allocated
    could be found and freed when the exit_mmap() function cleared the user
    address space. As a consequence, a kernel panic occurred. To fix this bug,
    the BUG_ON() function has been replaced by WARN_ON(), which prevents the
    kernel from panicking in the aforementioned situation. (BZ#1235930)

    All kernel users are advised to upgrade to these updated packages, which
    contain backported patches to correct these issues. The system must be
    rebooted for this update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2015/rhsa-2015_1583.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d166c2e0");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2015:1583");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1218074");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2015:1583.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3636");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(416);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/12");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:6.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '6.5')) audit(AUDIT_OS_NOT, 'Red Hat 6.5', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2015-3636');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2015:1583');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.5/x86_64/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/os',
      'content/aus/rhel/server/6/6.5/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.5/x86_64/os',
      'content/aus/rhel/server/6/6.5/x86_64/source/SRPMS',
      'content/eus/rhel/computenode/6/6.5/x86_64/debug',
      'content/eus/rhel/computenode/6/6.5/x86_64/optional/debug',
      'content/eus/rhel/computenode/6/6.5/x86_64/optional/os',
      'content/eus/rhel/computenode/6/6.5/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/6/6.5/x86_64/os',
      'content/eus/rhel/computenode/6/6.5/x86_64/sfs/debug',
      'content/eus/rhel/computenode/6/6.5/x86_64/sfs/os',
      'content/eus/rhel/computenode/6/6.5/x86_64/sfs/source/SRPMS',
      'content/eus/rhel/computenode/6/6.5/x86_64/source/SRPMS',
      'content/eus/rhel/power/6/6.5/ppc64/debug',
      'content/eus/rhel/power/6/6.5/ppc64/optional/debug',
      'content/eus/rhel/power/6/6.5/ppc64/optional/os',
      'content/eus/rhel/power/6/6.5/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/6/6.5/ppc64/os',
      'content/eus/rhel/power/6/6.5/ppc64/source/SRPMS',
      'content/eus/rhel/server/6/6.5/i386/debug',
      'content/eus/rhel/server/6/6.5/i386/highavailability/debug',
      'content/eus/rhel/server/6/6.5/i386/highavailability/os',
      'content/eus/rhel/server/6/6.5/i386/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.5/i386/loadbalancer/debug',
      'content/eus/rhel/server/6/6.5/i386/loadbalancer/os',
      'content/eus/rhel/server/6/6.5/i386/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.5/i386/optional/debug',
      'content/eus/rhel/server/6/6.5/i386/optional/os',
      'content/eus/rhel/server/6/6.5/i386/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.5/i386/os',
      'content/eus/rhel/server/6/6.5/i386/resilientstorage/debug',
      'content/eus/rhel/server/6/6.5/i386/resilientstorage/os',
      'content/eus/rhel/server/6/6.5/i386/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.5/i386/source/SRPMS',
      'content/eus/rhel/server/6/6.5/x86_64/debug',
      'content/eus/rhel/server/6/6.5/x86_64/highavailability/debug',
      'content/eus/rhel/server/6/6.5/x86_64/highavailability/os',
      'content/eus/rhel/server/6/6.5/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.5/x86_64/loadbalancer/debug',
      'content/eus/rhel/server/6/6.5/x86_64/loadbalancer/os',
      'content/eus/rhel/server/6/6.5/x86_64/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.5/x86_64/optional/debug',
      'content/eus/rhel/server/6/6.5/x86_64/optional/os',
      'content/eus/rhel/server/6/6.5/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.5/x86_64/os',
      'content/eus/rhel/server/6/6.5/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/6/6.5/x86_64/resilientstorage/os',
      'content/eus/rhel/server/6/6.5/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.5/x86_64/scalablefilesystem/debug',
      'content/eus/rhel/server/6/6.5/x86_64/scalablefilesystem/os',
      'content/eus/rhel/server/6/6.5/x86_64/scalablefilesystem/source/SRPMS',
      'content/eus/rhel/server/6/6.5/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/6/6.5/s390x/debug',
      'content/eus/rhel/system-z/6/6.5/s390x/optional/debug',
      'content/eus/rhel/system-z/6/6.5/s390x/optional/os',
      'content/eus/rhel/system-z/6/6.5/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/6/6.5/s390x/os',
      'content/eus/rhel/system-z/6/6.5/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-firmware-2.6.32-431.61.2.el6', 'sp':'5', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-2.6.32-431.61.2.el6', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
