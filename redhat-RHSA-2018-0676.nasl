#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0676. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108984);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/16");

  script_cve_id(
    "CVE-2016-3672",
    "CVE-2016-7913",
    "CVE-2016-8633",
    "CVE-2017-1000252",
    "CVE-2017-1000407",
    "CVE-2017-1000410",
    "CVE-2017-12154",
    "CVE-2017-12190",
    "CVE-2017-13166",
    "CVE-2017-13305",
    "CVE-2017-14140",
    "CVE-2017-15116",
    "CVE-2017-15121",
    "CVE-2017-15126",
    "CVE-2017-15127",
    "CVE-2017-15129",
    "CVE-2017-15265",
    "CVE-2017-15274",
    "CVE-2017-17448",
    "CVE-2017-17449",
    "CVE-2017-17558",
    "CVE-2017-18017",
    "CVE-2017-18203",
    "CVE-2017-7294",
    "CVE-2017-8824",
    "CVE-2017-9725",
    "CVE-2018-1000004",
    "CVE-2018-5750",
    "CVE-2018-6927"
  );
  script_xref(name:"RHSA", value:"2018:0676");

  script_name(english:"RHEL 7 : kernel-rt (RHSA-2018:0676)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2018:0676 advisory.

    The kernel-rt packages provide the Real Time Linux Kernel, which enables fine-tuning for systems with
    extremely high determinism requirements.

    Security Fix(es):

    * kernel: Buffer overflow in firewire driver via crafted incoming packets (CVE-2016-8633, Important)

    * kernel: Use-after-free vulnerability in DCCP socket (CVE-2017-8824, Important)

    * Kernel: kvm: nVMX: L2 guest could access hardware(L0) CR8 register (CVE-2017-12154, Important)

    * kernel: v4l2: disabled memory access protection mechanism allowing privilege escalation (CVE-2017-13166,
    Important)

    * kernel: media: use-after-free in [tuner-xc2028] media driver (CVE-2016-7913, Moderate)

    * kernel: drm/vmwgfx: fix integer overflow in vmw_surface_define_ioctl() (CVE-2017-7294, Moderate)

    * kernel: Incorrect type conversion for size during dma allocation (CVE-2017-9725, Moderate)

    * kernel: memory leak when merging buffers in SCSI IO vectors (CVE-2017-12190, Moderate)

    * kernel: vfs: BUG in truncate_inode_pages_range() and fuse client (CVE-2017-15121, Moderate)

    * kernel: Use-after-free in userfaultfd_event_wait_completion function in userfaultfd.c (CVE-2017-15126,
    Moderate)

    * kernel: net: double-free and memory corruption in get_net_ns_by_id() (CVE-2017-15129, Moderate)

    * kernel: Use-after-free in snd_seq_ioctl_create_port() (CVE-2017-15265, Moderate)

    * kernel: Incorrect handling in arch/x86/include/asm/mmu_context.h:init_new_context function allowing use-
    after-free (CVE-2017-17053, Moderate)

    * kernel: Missing capabilities check in net/netfilter/nfnetlink_cthelper.c allows for unprivileged access
    to systemwide nfnl_cthelper_list structure (CVE-2017-17448, Moderate)

    * kernel: Missing namespace check in net/netlink/af_netlink.c allows for network monitors to observe
    systemwide activity (CVE-2017-17449, Moderate)

    * kernel: Unallocated memory access by malicious USB device via bNumInterfaces overflow (CVE-2017-17558,
    Moderate)

    * kernel: netfilter: use-after-free in tcpmss_mangle_packet function in net/netfilter/xt_TCPMSS.c
    (CVE-2017-18017, Moderate)

    * kernel: Race condition in drivers/md/dm.c:dm_get_from_kobject() allows local users to cause a denial of
    service (CVE-2017-18203, Moderate)

    * kernel: kvm: Reachable BUG() on out-of-bounds guest IRQ (CVE-2017-1000252, Moderate)

    * Kernel: KVM: DoS via write flood to I/O port 0x80 (CVE-2017-1000407, Moderate)

    * kernel: Stack information leak in the EFS element (CVE-2017-1000410, Moderate)

    * kernel: Kernel address information leak in drivers/acpi/sbshc.c:acpi_smbus_hc_add() function potentially
    allowing KASLR bypass (CVE-2018-5750, Moderate)

    * kernel: Race condition in sound system can lead to denial of service (CVE-2018-1000004, Moderate)

    * kernel: unlimiting the stack disables ASLR (CVE-2016-3672, Low)

    * kernel: Missing permission check in move_pages system call (CVE-2017-14140, Low)

    * kernel: Null pointer dereference in rngapi_reset function (CVE-2017-15116, Low)

    * kernel: Improper error handling of VM_SHARED hugetlbfs mapping in mm/hugetlb.c (CVE-2017-15127, Low)

    * kernel: Integer overflow in futex.c:futux_requeue can lead to denial of service or unspecified impact
    (CVE-2018-6927, Low)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

    Red Hat would like to thank Eyal Itkin for reporting CVE-2016-8633; Mohamed Ghannam for reporting
    CVE-2017-8824; Jim Mattson (Google.com) for reporting CVE-2017-12154; Vitaly Mayatskih for reporting
    CVE-2017-12190; Andrea Arcangeli (Engineering) for reporting CVE-2017-15126; Kirill Tkhai for reporting
    CVE-2017-15129; Jan H. Schnherr (Amazon) for reporting CVE-2017-1000252; and Armis Labs for reporting
    CVE-2017-1000410. The CVE-2017-15121 issue was discovered by Miklos Szeredi (Red Hat) and the
    CVE-2017-15116 issue was discovered by ChunYu Wang (Red Hat).

    Additional Changes:

    See the Red Hat Enterprise Linux 7.5 Release Notes linked from References.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/7.5_Release_Notes/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74dc8666");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2018/rhsa-2018_0676.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbc4b9b7");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:0676");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1292927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1324749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1391490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1401061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1402885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1430418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1436798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1448770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1452589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1462329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1488329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1489088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1490781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1491224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1495089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1500894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1501878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1503749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1506255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1507270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1509264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1514609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1518274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1518638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1519160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1519591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1520328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1520893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1523481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1525218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1525474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1525762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1525768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1531135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1531174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1535315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1539706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1544612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1548412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1550811");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18017");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 125, 190, 20, 200, 248, 266, 284, 341, 362, 400, 416, 460, 476, 617, 681, 787, 863);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/11");

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
  var cve_list = make_list('CVE-2016-3672', 'CVE-2016-7913', 'CVE-2016-8633', 'CVE-2017-7294', 'CVE-2017-8824', 'CVE-2017-9725', 'CVE-2017-12154', 'CVE-2017-12190', 'CVE-2017-13166', 'CVE-2017-13305', 'CVE-2017-14140', 'CVE-2017-15116', 'CVE-2017-15121', 'CVE-2017-15126', 'CVE-2017-15127', 'CVE-2017-15129', 'CVE-2017-15265', 'CVE-2017-15274', 'CVE-2017-17448', 'CVE-2017-17449', 'CVE-2017-17558', 'CVE-2017-18017', 'CVE-2017-18203', 'CVE-2017-1000252', 'CVE-2017-1000407', 'CVE-2017-1000410', 'CVE-2018-5750', 'CVE-2018-6927', 'CVE-2018-1000004');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2018:0676');
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
      {'reference':'kernel-rt-3.10.0-862.rt56.804.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-3.10.0-862.rt56.804.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-3.10.0-862.rt56.804.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-3.10.0-862.rt56.804.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-3.10.0-862.rt56.804.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-doc-3.10.0-862.rt56.804.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-3.10.0-862.rt56.804.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-trace-3.10.0-862.rt56.804.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-trace-devel-3.10.0-862.rt56.804.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-trace-kvm-3.10.0-862.rt56.804.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
