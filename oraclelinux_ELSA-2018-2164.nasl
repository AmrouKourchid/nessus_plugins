#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-2164.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110996);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2018-3639",
    "CVE-2018-3665",
    "CVE-2018-10675",
    "CVE-2018-10872"
  );
  script_xref(name:"RHSA", value:"2018:2164");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2018-2164)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2018-2164 advisory.

    - [x86] entry/64: Don't use IST entry for #BP stack (Waiman Long) [1596113] {CVE-2018-10872}
    - [mm] mempolicy: fix use after free when calling get_mempolicy (Augusto Caringi) [1576757]
    {CVE-2018-10675}
    - [x86] virt_spec_ctrl: Set correct host SSDB value for AMD (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] spec_ctrl: Eliminate TIF_SSBD checks in IBRS on/off functions (Waiman Long) [1584356]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Disable SSBD update from scheduler if not user settable (Waiman Long) [1584356]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Make ssbd_enabled writtable (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] spec_ctrl: Remove thread_info check in __wrmsr_on_cpu() (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] spec_ctrl: Write per-thread SSBD state to spec_ctrl_pcp (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] spec_ctrl: Add a read-only ssbd_enabled debugfs file (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] bugs: Switch the selection of mitigation from CPU vendor to CPU features (Waiman Long) [1584356]
    {CVE-2018-3639}
    - [x86] bugs: Add AMD's SPEC_CTRL MSR usage (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] bugs: Add AMD's variant of SSB_NO (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] bugs/intel: Set proper CPU features and setup RDS (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] KVM/VMX: Emulate MSR_IA32_ARCH_CAPABILITIES (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] KVM: SVM: Implement VIRT_SPEC_CTRL support for SSBD (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] speculation, KVM: Implement support for VIRT_SPEC_CTRL/LS_CFG (Waiman Long) [1584356]
    {CVE-2018-3639}
    - [x86] bugs: Rework spec_ctrl base and mask logic (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] spec_ctrl: Rework SPEC_CTRL update after late microcode loading (Waiman Long) [1584356]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Make sync_all_cpus_ibrs() write spec_ctrl_pcp value (Waiman Long) [1584356]
    {CVE-2018-3639}
    - [x86] bugs: Unify x86_spec_ctrl_{set_guest, restore_host} (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] speculation: Rework speculative_store_bypass_update() (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] speculation: Add virtualized speculative store bypass disable support (Waiman Long) [1584356]
    {CVE-2018-3639}
    - [x86] bugs, KVM: Extend speculation control for VIRT_SPEC_CTRL (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] KVM: Rename KVM SPEC_CTRL MSR functions to match upstream (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] speculation: Handle HT correctly on AMD (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] cpufeatures: Add FEATURE_ZEN (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] cpufeatures: Disentangle SSBD enumeration (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] cpufeatures: Disentangle MSR_SPEC_CTRL enumeration from IBRS (Waiman Long) [1584356]
    {CVE-2018-3639}
    - [x86] speculation: Use synthetic bits for IBRS/IBPB/STIBP (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] bugs: Fix missing void (Waiman Long) [1584356] {CVE-2018-3639}
    - [documentation] spec_ctrl: Do some minor cleanups (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] speculation: Make 'seccomp' the default mode for Speculative Store Bypass (Waiman Long) [1584356]
    {CVE-2018-3639}
    - [kernel] seccomp: Move speculation migitation control to arch code (Waiman Long) [1584356]
    {CVE-2018-3639}
    - [kernel] seccomp: Use PR_SPEC_FORCE_DISABLE (Waiman Long) [1584356] {CVE-2018-3639}
    - [uapi] prctl: Add force disable speculation (Waiman Long) [1584356] {CVE-2018-3639}
    - [kernel] seccomp: Enable speculation flaw mitigations (Waiman Long) [1584356] {CVE-2018-3639}
    - [fs] proc: Provide details on speculation flaw mitigations (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] nospec: Allow getting/setting on non-current task (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] spec_ctrl: Show IBPB in the Spectre_v2 sysfs file (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] pti: Check MSR_IA32_ARCH_CAPABILITIES for Meltdown vulnearability (Waiman Long) [1584356]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Sync up naming of SPEC_CTRL MSR bits with upstream (Waiman Long) [1584356]
    {CVE-2018-3639}
    - [x86] pti: Fix kexec warning on debug kernel (Waiman Long) [1584356] {CVE-2018-3639}
    - [x86] kvm/fpu: Enable eager FPU restore (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] always enable eager FPU by default (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Load xsave pointer *after* initialization (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Fix 32-bit signal frame handling (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Always restore_xinit_state() when use_eager_cpu() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Rename drop_init_fpu() to fpu_reset_state() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Fix math_state_restore() race with kernel_fpu_begin() (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] fpu: Fold __drop_fpu() into its sole user (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Don't abuse drop_init_fpu() in flush_thread() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Introduce restore_init_xstate() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Document user_fpu_begin() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Factor out memset(xstate, 0) in fpu_finit() paths (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Change xstateregs_get()/set() to use ->xsave.i387 rather than ->fxsave (Paolo Bonzini)
    [1589047] {CVE-2018-3665}
    - [x86] fpu: Always allow FPU in interrupt if use_eager_fpu() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Don't abuse has_fpu in __kernel_fpu_begin/end() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Introduce per-cpu in_kernel_fpu state (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Check tsk_used_math() in kernel_fpu_end() for eager FPU (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] fpu: Change math_error() to use unlazy_fpu(), kill (now) unused save_init_fpu() (Paolo Bonzini)
    [1589047] {CVE-2018-3665}
    - [x86] Merge simd_math_error() into math_error() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Don't do __thread_fpu_end() if use_eager_fpu() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Don't reset thread.fpu_counter (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: shift drop_init_fpu() from save_xstate_sig() to handle_signal() (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] Allow FPU to be used at interrupt time even with eagerfpu (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] i387.c: Initialize thread xstate only on CPU0 only once (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] kvm: fix kvm's usage of kernel_fpu_begin/end() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] rhel: initialize scattered CPUID features early (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: make eagerfpu= boot param tri-state (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: enable eagerfpu by default for xsaveopt (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: decouple non-lazy/eager fpu restore from xsave (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: use non-lazy fpu restore for processors supporting xsave (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] fpu: remove unnecessary user_fpu_end() in save_xstate_sig() (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] fpu: drop_fpu() before restoring new state from sigframe (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Unify signal handling code paths for x86 and x86_64 kernels (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] fpu: drop the fpu state during thread exit (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] signals: ia32_signal.c: add __user casts to fix sparse warnings (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] fpu: Consolidate inline asm routines for saving/restoring fpu state (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] signal: Cleanup ifdefs and is_ia32, is_x32 (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu/xsave: Keep __user annotation in casts (Paolo Bonzini) [1589047] {CVE-2018-3665}
    (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] extable: Remove open-coded exception table entries in arch/x86/include/asm/xsave.h (Paolo Bonzini)
    [1589047] {CVE-2018-3665}
    into exported and internal interfaces (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] i387: Uninline the generic FP helpers that we expose to kernel modules (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] i387: (DON'T ACTUALLY) support lazy restore of FPU state (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] i387: use 'restore_fpu_checking()' directly in task switching code (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] i387: fix up some fpu_counter confusion (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] i387: re-introduce FPU state preloading at context switch time (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] i387: move TS_USEDFPU flag from thread_info to task_struct (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] i387: move AMD K7/K8 fpu fxsave/fxrstor workaround from save to restore (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] i387: do not preload FPU state at task switch time (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] i387: don't ever touch TS_USEDFPU directly, use helper functions (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] i387: move TS_USEDFPU clearing out of __save_init_fpu and into callers (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] i387: fix x86-64 preemption-unsafe user stack save/restore (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] i387: math_state_restore() isn't called from asm (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fix potentially dangerous trailing '; ' in #defined values/expressions (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] x86-32, fpu: Fix FPU exception handling on non-SSE systems (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] Fix common misspellings (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] kvm: Initialize fpu state in preemptible context (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Merge fpu_save_init() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] x86-32, fpu: Rewrite fpu_save_init() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Remove PSHUFB_XMM5_* macros (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Remove unnecessary ifdefs from i387 code. (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] x86-64, fpu: Simplify constraints for fxsave/fxtstor (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] x86-64, fpu: Fix cs value in convert_from_fxsr() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] x86-64, fpu: Disable preemption when using TS_USEDFPU (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Merge __save_init_fpu() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Merge tolerant_fwait() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] fpu: Merge fpu_init() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] xsave: Disable xsave in i387 emulation mode (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] xsave: Make xstate_enable_boot_cpu() __init, protect on CPU 0 (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] xsave: Add __init attribute to setup_xstate_features() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] xsave: Make init_xstate_buf static (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] xsave: Check cpuid level for XSTATE_CPUID (0x0d) (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] xsave: Introduce xstate enable functions (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] xsave: Do not include asm/i387.h in asm/xsave.h (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] Avoid unnecessary __clear_user() and xrstor in signal handling (Paolo Bonzini) [1589047]
    {CVE-2018-3665}
    - [x86] xsave: Cleanup return codes in check_for_xstate() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] xsave: Separate fpu and xsave initialization (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] xsave: Move boot cpu initialization to xsave_init() (Paolo Bonzini) [1589047] {CVE-2018-3665}
    - [x86] Revert '[x86] fpu: change save_i387_xstate() to rely on unlazy_fpu()' (Paolo Bonzini) [1589047]
    {CVE-2018-3665}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-2164.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10675");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/11");

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
  var fixed_uptrack_levels = ['2.6.32-754.2.1.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-2164');
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
    {'reference':'kernel-2.6.32-754.2.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-abi-whitelists-2.6.32-754.2.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-2.6.32'},
    {'reference':'kernel-debug-2.6.32-754.2.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-754.2.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-754.2.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-754.2.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-754.2.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-754.2.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-754.2.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.32-754.2.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-abi-whitelists-2.6.32-754.2.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-2.6.32'},
    {'reference':'kernel-debug-2.6.32-754.2.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-754.2.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-754.2.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-754.2.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-754.2.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-754.2.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-754.2.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
