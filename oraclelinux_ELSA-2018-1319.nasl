#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-1319.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109629);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/24");

  script_cve_id(
    "CVE-2017-7645",
    "CVE-2017-8824",
    "CVE-2017-13166",
    "CVE-2017-18017",
    "CVE-2017-1000410",
    "CVE-2018-8897"
  );
  script_xref(name:"RHSA", value:"2018:1319");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2018-1319)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2018-1319 advisory.

    - [x86] entry/64: Don't use IST entry for #BP stack (Waiman Long) [1567078 1567079] {CVE-2018-8897}
    - [x86] pti: Disable kaiser_add_mapping if X86_FEATURE_NOPTI (Waiman Long) [1561441 1557562]
    {CVE-2017-5754}
    - [x86] irq/ioapic: Check for valid irq_cfg pointer in smp_irq_move_cleanup_interrupt (Waiman Long)
    [1553283 1550599] {CVE-2017-5754}
    - [x86] kexec/64: Clear control page after PGD init (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] efi/64: Fix potential PTI data corruption problem (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] pti/mm: Fix machine check with PTI on old AMD CPUs (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] pti/mm: Enable PAGE_GLOBAL if not affected by Meltdown (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] retpoline: Avoid retpolines for built-in __init functions (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] kexec/32: Allocate 8k PGD for PTI (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] spec_ctrl: Patch out lfence on old 32-bit CPUs (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] cpufeature: Blacklist SPEC_CTRL/PRED_CMD on early Spectre v2 microcodes (Waiman Long) [1553283
    1550599] {CVE-2017-5754}
    - [x86] spec_ctrl/32: Enable IBRS processing on kernel entries & exits (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] spec_ctrl/32: Stuff RSB on kernel entry (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] pti: Allow CONFIG_PAGE_TABLE_ISOLATION for x86_32 (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] pti/32: Add a PAE specific version of __pti_set_user_pgd (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] mm/dump_pagetables: Support PAE page table dumping (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] pgtable/pae: Use separate kernel PMDs for user page-table (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] mm/pae: Populate valid user PGD entries (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] pti: Enable x86-32 for kaiser.c (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] pti: Disable PCID handling in x86-32 TLB flushing code (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] pgtable: Disable user PGD poisoning for PAE (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] pgtable: Move more PTI functions out of pgtable_64.h (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] pgtable: Move pgdp kernel/user conversion functions to pgtable.h (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] pgtable/32: Allocate 8k page-tables when PTI is enabled (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] pgtable/pae: Unshare kernel PMDs when PTI is enabled (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] entry/32: Handle debug exception similar to NMI (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] entry/32: Add PTI cr3 switch to non-NMI entry/exit points (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] entry/32: Add PTI cr3 switches to NMI handler code (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] entry/32: Introduce SAVE_ALL_NMI and RESTORE_ALL_NMI (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] entry/32: Enable the use of trampoline stack (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] entry/32: Change INT80 to be an interrupt gate (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] entry/32: Handle Entry from Kernel-Mode on Entry-Stack (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] entry/32: Leave the kernel via trampoline stack (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] entry/32: Enter the kernel via trampoline stack (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] entry/32: Restore segments before int registers (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] entry/32: Split off return-to-kernel path (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] entry/32: Unshare NMI return path (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] entry/32: Put ESPFIX code into a macro (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] entry/32: Load task stack from x86_tss.sp1 in SYSENTER handler (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] entry/32: Rename TSS_sysenter_sp0 to TSS_entry_stack (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] pti: Add X86_FEATURE_NOPTI to permanently disable PTI (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] entry/32: Simplify and fix up the SYSENTER stack #DB/NMI fixup (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] doublefault: Set the right gs register for doublefault (Waiman Long) [1553283 1550599]
    {CVE-2017-5754}
    - [x86] syscall: int80 must not clobber r12-15 (Waiman Long) [1553283 1550599] {CVE-2017-5754}
    - [x86] syscall: change ia32_syscall() to create the full register frame in ia32_do_call() (Waiman Long)
    [1553283 1550599] {CVE-2017-5754}
    - [x86] cve: Make all Meltdown/Spectre percpu variables available to x86-32 (Waiman Long) [1553283
    1550599] {CVE-2017-5754}
    - [net] dccp: use-after-free in DCCP code (Stefano Brivio) [1520818 1520817] {CVE-2017-8824}
    - [fs] nfsd: check for oversized NFSv2/v3 arguments (J. Bruce Fields) [1447640 1447641] {CVE-2017-7645}
    - [v4l] media: v4l2-compat-ioctl32.c: refactor compat ioctl32 logic fixup (Jarod Wilson) [1548429 1548432]
    {CVE-2017-13166}
    - [v4l] media: v4l2-compat-ioctl32.c: refactor compat ioctl32 logic (Jarod Wilson) [1548429 1548432]
    {CVE-2017-13166}
    - [net] netfilter: xt_TCPMSS: add more sanity tests on tcph->doff (Florian Westphal) [1543089 1543091]
    {CVE-2017-18017}
    - [net] netfilter: xt_TCPMSS: fix handling of malformed TCP header and options (Florian Westphal) [1543089
    1543091] {CVE-2017-18017}
    - [net] netfilter: xt_TCPMSS: SYN packets are allowed to contain data (Florian Westphal) [1543089 1543091]
    {CVE-2017-18017}
    - [net] bluetooth: Prevent uninitialized data (Gopal Tiwari) [1519627 1519626] {CVE-2017-1000410}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-1319.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18017");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.32-696.28.1.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-1319');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '2.6';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-2.6.32-696.28.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-abi-whitelists-2.6.32-696.28.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-2.6.32'},
    {'reference':'kernel-debug-2.6.32-696.28.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-696.28.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-696.28.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-696.28.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-696.28.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-696.28.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-696.28.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.32-696.28.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-abi-whitelists-2.6.32-696.28.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-2.6.32'},
    {'reference':'kernel-debug-2.6.32-696.28.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-696.28.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-696.28.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-696.28.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-696.28.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-696.28.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-696.28.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-abi-whitelists / kernel-debug / etc');
}
