#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-0008.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105599);
  script_version("3.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"RHSA", value:"2018:0008");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2018-0008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2018-0008 advisory.

    - [x86] spec_ctrl: svm: spec_ctrl at vmexit needs per-cpu areas functional (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: Eliminate redundnat FEATURE Not Present messages (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: enable IBRS and stuff_RSB before calling NMI C code (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: skip CAP_SYS_PTRACE check to skip audit (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: disable ibrs while in intel_idle() (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: skip IBRS/CR3 restore when paranoid exception returns to userland (Waiman Long)
    [1519797 1519796] {CVE-2017-5715}
    - Revert 'x86/entry: Use retpoline for syscall's indirect calls' (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] mm/dump_pagetables: Allow dumping current pagetables (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/dump_pagetables: Add a pgd argument to walk_pgd_level() (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/dump_pagetables: Add page table directory (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] entry: Remove unneeded nmi_userspace code (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] entry: Fix nmi exit code with CONFIG_TRACE_IRQFLAGS (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: init_tss is supposed to go in the PAGE_ALIGNED per-cpu section (Waiman Long) [1519799
    1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: Clear kdump pgd page to prevent incorrect behavior (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: consider the init_mm.pgd a kaiser pgd (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: convert userland visible 'kpti' name to 'pti' (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] spec_ctrl: set IBRS during resume from RAM if ibrs_enabled is 2 (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] mm/kaiser: __load_cr3 in resume from RAM after kernel %gs has been restored (Waiman Long) [1519797
    1519796] {CVE-2017-5715}
    - [x86] mm/kaiser: Revert the __GFP_COMP flag change (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] entry: Fix paranoid_exit() trampoline clobber (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] spec_ctrl: allow use_ibp_disable only if both SPEC_CTRL and IBPB_SUPPORT are missing (Waiman Long)
    [1519797 1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: Documentation spec_ctrl.txt (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: remove irqs_disabled() check from intel_idle() (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: use enum when setting ibrs/ibpb_enabled (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: undo speculation barrier for ibrs_enabled and noibrs_cmdline (Waiman Long) [1519797
    1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: introduce ibpb_enabled = 2 for IBPB instead of IBRS (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: introduce SPEC_CTRL_PCP_ONLY_IBPB (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: cleanup s/flush/sync/ naming when sending IPIs (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: set IBRS during CPU init if in ibrs_enabled == 2 (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: use IBRS_ENABLED instead of 1 (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: allow the IBP disable feature to be toggled at runtime (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: always initialize save_reg in ENABLE_IBRS_SAVE_AND_CLOBBER (Waiman Long) [1519797
    1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: ibrs_enabled() is expected to return > 1 (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: CLEAR_EXTRA_REGS and extra regs save/restore (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] syscall: Clear unused extra registers on syscall (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] entry: Add back STUFF_RSB to interrupt and error paths (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] mm/kaiser: make is_kaiser_pgd reliable (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: disable global pages by default with KAISER (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] revert: mm/kaiser: Disable global pages by default with KAISER (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] kaiser/mm: fix pgd freeing in error path (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] entry: Fix 32-bit program crash with 64-bit kernel on AMD boxes (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: reload spec_ctrl cpuid in all microcode load paths (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: Prevent unwanted speculation without IBRS (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: add noibrs noibpb boot options (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] entry: Use retpoline for syscall's indirect calls (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] syscall: Clear unused extra registers on 32-bit compatible syscall entrance (Waiman Long) [1519797
    1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: rescan cpuid after a late microcode update (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: add debugfs ibrs_enabled ibpb_enabled (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: consolidate the spec control boot detection (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] Remove __cpuinitdata from some data & function (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] KVM/spec_ctrl: allow IBRS to stay enabled in host userland (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: move stuff_RSB in spec_ctrl.h (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] entry: Remove STUFF_RSB in error and interrupt code (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] entry: Stuff RSB for entry to kernel for non-SMEP platform (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] mm: Only set IBPB when the new thread cannot ptrace (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] mm: Set IBPB upon context switch (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] idle: Disable IBRS when offlining cpu and re-enable (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] idle: Disable IBRS entering idle and enable it on wakeup (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: implement spec ctrl C methods (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: save IBRS MSR value in save_paranoid for NMI (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] enter: Use IBRS on syscall and interrupts (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] spec_ctrl: swap rdx with rsi for nmi nesting detection (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: spec_ctrl_pcp and kaiser_enabled_pcp in same cachline (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] spec_ctrl: use per-cpu knob instead of ALTERNATIVES for ibpb and ibrs (Waiman Long) [1519797
    1519796] {CVE-2017-5715}
    - [x86] enter: MACROS to set/clear IBRS and set IBPB (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [kvm] x86: add SPEC_CTRL to MSR and CPUID lists (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [kvm] svm: add MSR_IA32_SPEC_CTRL and MSR_IA32_PRED_CMD (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] svm: Set IBPB when running a different VCPU (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [kvm] vmx: add MSR_IA32_SPEC_CTRL and MSR_IA32_PRED_CMD (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [kvm] vmx: Set IBPB when running a different VCPU (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [kvm] x86: clear registers on VM exit (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] [kvm] Pad RSB on VM transition (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [security] Add SPEC_CTRL Kconfig option (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] cpu/AMD: Control indirect branch predictor when SPEC_CTRL not available (Waiman Long) [1519797
    1519796] {CVE-2017-5715}
    - [x86] feature: Report presence of IBPB and IBRS control (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] feature: Enable the x86 feature to control Speculation (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] cpuid: Provide get_scattered_cpuid_leaf() (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] cpuid: Cleanup cpuid_regs definitions (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] microcode: Share native MSR accessing variants (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] nop: Make the ASM_NOP* macros work from assembly (Waiman Long) [1519797 1519796] {CVE-2017-5715}
    - [x86] cpu: Clean up and unify the NOP selection infrastructure (Waiman Long) [1519797 1519796]
    {CVE-2017-5715}
    - [x86] entry: Further simplify the paranoid_exit code (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] entry: Remove trampoline check from paranoid entry path (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] entry: Don't switch to trampoline stack in paranoid_exit (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] entry: Simplify trampoline stack restore code (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [misc] locking/barriers: prevent speculative execution based on Coverity scan results (Waiman Long)
    [1519787 1519789] {CVE-2017-5753}
    - [fs] udf: prevent speculative execution (Waiman Long) [1519787 1519789] {CVE-2017-5753}
    - [fs] prevent speculative execution (Waiman Long) [1519787 1519789] {CVE-2017-5753}
    - [scsi] qla2xxx: prevent speculative execution (Waiman Long) [1519787 1519789] {CVE-2017-5753}
    - [netdrv] p54: prevent speculative execution (Waiman Long) [1519787 1519789] {CVE-2017-5753}
    - [netdrv] carl9170: prevent speculative execution (Waiman Long) [1519787 1519789] {CVE-2017-5753}
    - [media] uvcvideo: prevent speculative execution (Waiman Long) [1519787 1519789] {CVE-2017-5753}
    - [x86] cpu/AMD: Remove now unused definition of MFENCE_RDTSC feature (Waiman Long) [1519787 1519789]
    {CVE-2017-5753}
    - [x86] cpu/AMD: Make the LFENCE instruction serialized (Waiman Long) [1519787 1519789] {CVE-2017-5753}
    - [kernel] locking/barriers: introduce new memory barrier gmb() (Waiman Long) [1519787 1519789]
    {CVE-2017-5753}
    - [x86] Fix typo preventing msr_set/clear_bit from having an effect (Waiman Long) [1519787 1519789]
    {CVE-2017-5753}
    - [x86] Add another set of MSR accessor functions (Waiman Long) [1519787 1519789] {CVE-2017-5753}
    - [x86] mm/kaiser: Replace kaiser with kpti to sync with upstream (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: map the trace idt tables in userland shadow pgd (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: add 'kaiser' and 'nokaiser' boot options (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] kaiser/mm: fix RESTORE_CR3 crash in kaiser_stop_machine (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: use stop_machine for enable/disable knob (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] kaiser/mm: use atomic ops to poison/unpoison user pagetables (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: use invpcid to flush the two kaiser PCID AISD (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: use two PCID ASIDs optimize the TLB during enter/exit kernel (Waiman Long) [1519799
    1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: stop patching flush_tlb_single (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm: If INVPCID is available, use it to flush global mappings (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: use PCID feature to make user and kernel switches faster (Waiman Long) [1519799
    1519802] {CVE-2017-5754}
    - [x86] mm/64: Initialize CR4.PCIDE early (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm: Add a 'noinvpcid' boot option to turn off INVPCID (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm: Add the 'nopcid' boot option to turn off PCID (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: validate trampoline stack (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] entry: Move SYSENTER_stack to the beginning of struct tss_struct (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: isolate the user mapped per cpu areas (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: selective boot time defaults (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser/xen: Dynamically disable KAISER when running under Xen PV (Waiman Long) [1519799
    1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: add Kconfig (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: avoid false positives during non-kaiser pgd updates (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: Respect disabled CPU features (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] kaiser/mm: trampoline stack comments (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: stack trampoline (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: re-enable vsyscalls (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: allow to build KAISER with KASRL (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: allow KAISER to be enabled/disabled at runtime (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: un-poison PGDs at runtime (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: add a function to check for KAISER being enabled (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: add debugfs file to turn KAISER on/off at runtime (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: disable native VSYSCALL (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: map virtually-addressed performance monitoring buffers (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: add kprobes text section (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: map trace interrupt entry (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: map entry stack per-cpu areas (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: map dynamically-allocated LDTs (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: make sure static PGDs are 8k in size (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: allow NX poison to be set in p4d/pgd (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: unmap kernel from userspace page tables (core patch) (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: mark per-cpu data structures required for entry/exit (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: introduce user-mapped per-cpu areas (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: add cr3 switches to entry code (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: remove scratch registers (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/kaiser: prepare assembly for entry/exit CR3 switching (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm/kaiser: Disable global pages by default with KAISER (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] mm: Document X86_CR4_PGE toggling behavior (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm/tlb: Make CR4-based TLB flushes more robust (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm: Do not set _PAGE_USER for init_mm page tables (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] increase robusteness of bad_iret fixup handler (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [x86] mm: Check if PUD is large when validating a kernel address (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [x86] Separate out entry text section (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [include] linux/const.h: Add _BITUL() and _BITULL() (Waiman Long) [1519799 1519802] {CVE-2017-5754}
    - [include] linux/mmdebug.h: add VM_WARN_ON() and VM_WARN_ON_ONCE() (Waiman Long) [1519799 1519802]
    {CVE-2017-5754}
    - [include] stddef.h: Move offsetofend() from vfio.h to a generic kernel header (Waiman Long) [1519799
    1519802] {CVE-2017-5754}
    - [kernel] mqueue: fix a use-after-free in sys_mq_notify() (Davide Caratti) [1476122 1476124]
    {CVE-2017-11176}
    - [net] ipv6: accept 64k - 1 packet length in ip6_find_1stfragopt() (Matteo Croce) [1477008 1477006]
    {CVE-2017-7542}
    - [net] ipv6: avoid overflow of offset in ip6_find_1stfragopt (Matteo Croce) [1477008 1477006]
    {CVE-2017-7542}
    - [net] ipv6: Fix leak in ipv6_gso_segment() (Sabrina Dubroca) [1502417 1459951] {CVE-2017-9074}
    - [net] gre: fix a possible skb leak (Sabrina Dubroca) [1502417 1459951] {CVE-2017-9074}
    - [net] ipv6: xfrm: Handle errors reported by xfrm6_find_1stfragopt() (Sabrina Dubroca) [1502417 1459951]
    {CVE-2017-9074}
    - [net] ipv6: Check ip6_find_1stfragopt() return value properly (Sabrina Dubroca) [1502417 1459951]
    {CVE-2017-9074}
    - [net] ipv6: Prevent overrun when parsing v6 header options (Sabrina Dubroca) [1502417 1459951]
    {CVE-2017-9074}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-0008.html");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.32-696.18.7.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-0008');
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
    {'reference':'kernel-2.6.32-696.18.7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-abi-whitelists-2.6.32-696.18.7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-2.6.32'},
    {'reference':'kernel-debug-2.6.32-696.18.7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-696.18.7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-696.18.7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-696.18.7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-696.18.7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-696.18.7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-696.18.7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.32-696.18.7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-abi-whitelists-2.6.32-696.18.7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-2.6.32'},
    {'reference':'kernel-debug-2.6.32-696.18.7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-696.18.7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-696.18.7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-696.18.7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-696.18.7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-696.18.7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-696.18.7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
