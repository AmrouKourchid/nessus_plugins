#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-0007.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105598);
  script_version("3.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"RHSA", value:"2018:0007");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2018-0007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2018-0007 advisory.

    - [x86] spec_ctrl: Eliminate redundant FEATURE Not Present messages (Andrea Arcangeli) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] mm/kaiser: init_tss is supposed to go in the PAGE_ALIGNED per-cpu section (Andrea Arcangeli)
    [1519795 1519798] {CVE-2017-5715}
    - [x86] spec_ctrl: svm: spec_ctrl at vmexit needs per-cpu areas functional (Andrea Arcangeli) [1519795
    1519798] {CVE-2017-5715}
    - [x86] kaiser/mm: skip IBRS/CR3 restore when paranoid exception returns to userland (Andrea Arcangeli)
    [1519795 1519798] {CVE-2017-5715}
    - [x86] kaiser/mm: consider the init_mm.pgd a kaiser pgd (Andrea Arcangeli) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] spec_ctrl: Prevent unwanted speculation without IBRS (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715 CVE-2017-5754}
    - [x86] entry: Remove trampoline check from paranoid entry path (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715 CVE-2017-5754}
    - [x86] entry: Fix paranoid_exit() trampoline clobber (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715
    CVE-2017-5754}
    - [x86] entry: Simplify trampoline stack restore code (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715
    CVE-2017-5754}
    - [x86] spec_ctrl: remove SPEC_CTRL_DEBUG code (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715}
    - [x86] spec_ctrl: add noibrs noibpb boot options (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715}
    - [x86] entry: Use retpoline for syscall's indirect calls (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] syscall: Clear unused extra registers on 32-bit compatible syscall entrance (Josh Poimboeuf)
    [1519795 1519798] {CVE-2017-5715}
    - [x86] spec_ctrl: cleanup unnecessary ptregscall_common function (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] spec_ctrl: CLEAR_EXTRA_REGS and extra regs save/restore (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] syscall: Clear unused extra registers on syscall entrance (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] spec_ctrl: rescan cpuid after a late microcode update (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] spec_ctrl: add debugfs ibrs_enabled ibpb_enabled (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] spec_ctrl: consolidate the spec control boot detection (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] KVM/spec_ctrl: allow IBRS to stay enabled in host userland (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] spec_ctrl: add debug aid to test the entry code without microcode (Josh Poimboeuf) [1519795
    1519798] {CVE-2017-5715}
    - [x86] spec_ctrl: move stuff_RSB in spec_ctrl.h (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715}
    - [x86] entry: Stuff RSB for entry to kernel for non-SMEP platform (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] mm: Only set IBPB when the new thread cannot ptrace current thread (Josh Poimboeuf) [1519795
    1519798] {CVE-2017-5715}
    - [x86] mm: Set IBPB upon context switch (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715}
    - [x86] idle: Disable IBRS when offlining cpu and re-enable on wakeup (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] idle: Disable IBRS entering idle and enable it on wakeup (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] spec_ctrl: implement spec ctrl C methods (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715}
    - [x86] spec_ctrl: save IBRS MSR value in save_paranoid for NMI (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] enter: Use IBRS on syscall and interrupts (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715}
    - [x86] spec_ctrl: swap rdx with rsi for nmi nesting detection (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] spec_ctrl: spec_ctrl_pcp and kaiser_enabled_pcp in same cachline (Josh Poimboeuf) [1519795
    1519798] {CVE-2017-5715}
    - [x86] spec_ctrl: use per-cpu knob instead of ALTERNATIVES for ibpb and ibrs (Josh Poimboeuf) [1519795
    1519798] {CVE-2017-5715}
    - [x86] enter: MACROS to set/clear IBRS and set IBPB (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715}
    - [kvm] x86: add SPEC_CTRL to MSR and CPUID lists (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715}
    - [kvm] svm: add MSR_IA32_SPEC_CTRL and MSR_IA32_PRED_CMD (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] svm: Set IBPB when running a different VCPU (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715}
    - [kvm] vmx: add MSR_IA32_SPEC_CTRL and MSR_IA32_PRED_CMD (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [kvm] vmx: Set IBPB when running a different VCPU (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715}
    - [kvm] x86: clear registers on VM exit (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715}
    - [x86] kvm: pad RSB on VM transition (Josh Poimboeuf) [1519795 1519798] {CVE-2017-5715}
    - [x86] cpu/AMD: Control indirect branch predictor when SPEC_CTRL not available (Josh Poimboeuf) [1519795
    1519798] {CVE-2017-5715}
    - [x86] feature: Report presence of IBPB and IBRS control (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [x86] feature: Enable the x86 feature to control Speculation (Josh Poimboeuf) [1519795 1519798]
    {CVE-2017-5715}
    - [tools] objtool: Don't print 'call dest' warnings for ignored functions (Josh Poimboeuf) [1519795
    1519798] {CVE-2017-5715}
    - [misc] locking/barriers: prevent speculative execution based on Coverity scan results (Josh Poimboeuf)
    [1519788 1519786] {CVE-2017-5753}
    - [fs] udf: prevent speculative execution (Josh Poimboeuf) [1519788 1519786] {CVE-2017-5753}
    - [fs] prevent speculative execution (Josh Poimboeuf) [1519788 1519786] {CVE-2017-5753}
    - [kernel] userns: prevent speculative execution (Josh Poimboeuf) [1519788 1519786] {CVE-2017-5753}
    - [scsi] qla2xxx: prevent speculative execution (Josh Poimboeuf) [1519788 1519786] {CVE-2017-5753}
    - [netdrv] p54: prevent speculative execution (Josh Poimboeuf) [1519788 1519786] {CVE-2017-5753}
    - [netdrv] carl9170: prevent speculative execution (Josh Poimboeuf) [1519788 1519786] {CVE-2017-5753}
    - [media] uvcvideo: prevent speculative execution (Josh Poimboeuf) [1519788 1519786] {CVE-2017-5753}
    - [x86] cpu/AMD: Remove now unused definition of MFENCE_RDTSC feature (Josh Poimboeuf) [1519788 1519786]
    {CVE-2017-5753}
    - [x86] cpu/AMD: Make the LFENCE instruction serialized (Josh Poimboeuf) [1519788 1519786] {CVE-2017-5753}
    - [misc] locking/barriers: introduce new memory barrier gmb() (Josh Poimboeuf) [1519788 1519786]
    {CVE-2017-5753}
    - [x86] mm/kaiser: Replace kaiser with kpti to sync with upstream (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: add 'kaiser' and 'nokaiser' boot options (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: map the trace idt tables in userland shadow pgd (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: fix RESTORE_CR3 crash in kaiser_stop_machine (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: use stop_machine for enable/disable knob (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: use atomic ops to poison/unpoison user pagetables (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: use invpcid to flush the two kaiser PCID AISD (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: use two PCID ASIDs optimize the TLB during enter/exit kernel (Josh Poimboeuf) [1519800
    1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: stop patching flush_tlb_single (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: use PCID feature to make user and kernel switches faster (Josh Poimboeuf) [1519800
    1519801] {CVE-2017-5754}
    - [x86] mm: If INVPCID is available, use it to flush global mappings (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/64: Fix reboot interaction with CR4.PCIDE (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/64: Initialize CR4.PCIDE early (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm: Add a 'noinvpcid' boot option to turn off INVPCID (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm: Add the 'nopcid' boot option to turn off PCID (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: validate trampoline stack (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] entry: Move SYSENTER_stack to the beginning of struct tss_struct (Josh Poimboeuf) [1519800
    1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: isolate the user mapped per cpu areas (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: enable kaiser in build (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: selective boot time defaults (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: handle call to xen_pv_domain() on PREEMPT_RT (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser/xen: Dynamically disable KAISER when running under Xen PV (Josh Poimboeuf) [1519800
    1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: add Kconfig (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: avoid false positives during non-kaiser pgd updates (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: Respect disabled CPU features (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: trampoline stack comments (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: stack trampoline (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: remove paravirt clock warning (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: re-enable vsyscalls (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: allow to build KAISER with KASRL (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: allow KAISER to be enabled/disabled at runtime (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: un-poison PGDs at runtime (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: add a function to check for KAISER being enabled (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: add debugfs file to turn KAISER on/off at runtime (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: disable native VSYSCALL (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: map virtually-addressed performance monitoring buffers (Josh Poimboeuf) [1519800
    1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: map debug IDT tables (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: add kprobes text section (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: map trace interrupt entry (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: map entry stack per-cpu areas (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: map dynamically-allocated LDTs (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: make sure static PGDs are 8k in size (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: allow NX poison to be set in p4d/pgd (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: unmap kernel from userspace page tables (core patch) (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: mark per-cpu data structures required for entry/exit (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: introduce user-mapped per-cpu areas (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: add cr3 switches to entry code (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: remove scratch registers (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/kaiser: prepare assembly for entry/exit CR3 switching (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm/kaiser: Disable global pages by default with KAISER (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] mm: Document X86_CR4_PGE toggling behavior (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm/tlb: Make CR4-based TLB flushes more robust (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [x86] mm: Do not set _PAGE_USER for init_mm page tables (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [x86] increase robusteness of bad_iret fixup handler (Josh Poimboeuf) [1519800 1519801] {CVE-2017-5754}
    - [perf] x86/intel/uncore: Fix memory leaks on allocation failures (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [mm] userfaultfd: hugetlbfs: prevent UFFDIO_COPY to fill beyond the end of i_size (Josh Poimboeuf)
    [1519800 1519801] {CVE-2017-5754}
    - [fs] userfaultfd: non-cooperative: fix fork use after free (Josh Poimboeuf) [1519800 1519801]
    {CVE-2017-5754}
    - [mm] userfaultfd: hugetlbfs: remove superfluous page unlock in VM_SHARED case (Josh Poimboeuf) [1519800
    1519801] {CVE-2017-5754}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-0007.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5754");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['3.10.0-693.11.6.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-0007');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '3.10';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-3.10.0-693.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-693.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-693.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-693.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-693.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-693.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-693.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-693.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-693.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-693.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-693.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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
