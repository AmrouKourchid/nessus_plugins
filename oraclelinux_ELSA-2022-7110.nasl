#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-7110.
##

include('compat.inc');

if (description)
{
  script_id(166553);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2022-0494",
    "CVE-2022-1353",
    "CVE-2022-23816",
    "CVE-2022-2588",
    "CVE-2022-23825",
    "CVE-2022-29900",
    "CVE-2022-29901"
  );
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Oracle Linux 8 : kernel (ELSA-2022-7110)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-7110 advisory.

    - debug: lockdown kgdb [Orabug: 34270802] {CVE-2022-21499}
    - intel_idle: Fix false positive RCU splats due to incorrect hardirqs state (Waiman Long) [2103167
    2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/spec_ctrl: Enable RHEL only ibrs_always & retpoline,ibrs_user spectre_v2 options (Waiman Long)
    [2103167 2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - KVM: emulate: do not adjust size of fastop and setcc subroutines (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/kvm: fix FASTOP_SIZE when return thunks are enabled (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - efi/x86: use naked RET on mixed mode call wrapper (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Remove apostrophe typo (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/speculation: Use DECLARE_PER_CPU for x86_spec_ctrl_current (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/entry: Remove UNTRAIN_RET from native_irq_return_ldt (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Mark retbleed_strings static (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/asm/32: Fix ANNOTATE_UNRET_SAFE use on 32-bit (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/speculation: Disable RRSBA behavior (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/kexec: Disable RET on kexec (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Do not enable IBPB-on-entry when IBPB is not supported (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Add Cannon lake to RETBleed affected CPU list (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - redhat/configs: Add new mitigation configs for RetBleed CVEs (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/retbleed: Add fine grained Kconfig knobs (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/cpu/amd: Enumerate BTC_NO (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/common: Stamp out the stepping madness (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - KVM: VMX: Prevent RSB underflow before vmenter (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/speculation: Fill RSB on vmexit for IBRS (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - KVM: VMX: Fix IBRS handling after vmexit (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - KVM: VMX: Prevent guest RSB poisoning attacks with eIBRS (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - KVM: VMX: Convert launched argument to flags (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - KVM: VMX: Flatten __vmx_vcpu_run() (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/speculation: Remove x86_spec_ctrl_mask (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/speculation: Use cached host SPEC_CTRL value for guest entry/exit (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/speculation: Fix SPEC_CTRL write on SMT state change (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/speculation: Fix firmware entry SPEC_CTRL handling (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/cpu/amd: Add Spectral Chicken (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Do IBPB fallback check only once (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Add retbleed=ibpb (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - objtool: Update Retpoline validation (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - intel_idle: Disable IBRS during long idle (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Report Intel retbleed vulnerability (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Split spectre_v2_select_mitigation() and spectre_v2_user_select_mitigation() (Waiman Long)
    [2103167 2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/speculation: Add spectre_v2=ibrs option to support Kernel IBRS (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Optimize SPEC_CTRL MSR writes (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/entry: Add kernel IBRS implementation (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Keep a per-CPU IA32_SPEC_CTRL value (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Enable STIBP for JMP2RET (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Add AMD retbleed= boot parameter (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/bugs: Report AMD retbleed vulnerability (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86: Add magic AMD return-thunk (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86: Use return-thunk in asm code (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/sev: Avoid using __x86_return_thunk (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/vsyscall_emu/64: Don't use RET in vsyscall emulation (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/kvm: Fix SETcc emulation for return thunks (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/bpf: Use alternative RET encoding (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/ftrace: Use alternative RET encoding (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86,objtool: Create .return_sites (Josh Poimboeuf) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86: Undo return-thunk damage (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/retpoline: Use -mfunction-return (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/retpoline: Swizzle retpoline thunk (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/retpoline: Cleanup some #ifdefery (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/cpufeatures: Move RETPOLINE flags to word 11 (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/kvm/vmx: Make noinstr clean (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - arch/x86/boot/compressed: Add -D__DISABLE_EXPORTS to kbuild flags (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86: (Ab)use __DISABLE_EXPORTS to disable RETHUNK in real mode (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/entry: Remove skip_r11rcx (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - cpuidle,intel_idle: Fix CPUIDLE_FLAG_IRQ_ENABLE (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/speculation/srbds: Do not try to turn mitigation off when not supported (Waiman Long) [2103167
    2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/ibt,paravirt: Use text_gen_insn() for paravirt_patch() (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/text-patching: Make text_gen_insn() play nice with ANNOTATE_NOENDBR (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/module: Fix the paravirt vs alternative order (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86: Add straight-line-speculation mitigation (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86: Prepare inline-asm for straight-line-speculation (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86: Prepare asm files for straight-line-speculation (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86: Use -mindirect-branch-cs-prefix for RETPOLINE builds (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86: Move RETPOLINE*_CFLAGS to arch Makefile (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/entry: Add a fence for kernel entry SWAPGS in paranoid_entry() (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - Makefile: remove stale cc-option checks (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - tools headers: Remove broken definition of __LITTLE_ENDIAN (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - tools arch: Update arch/x86/lib/mem{cpy,set}_64.S copies used in 'perf bench mem memcpy' (Waiman Long)
    [2103167 2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86: Add insn_decode_kernel() (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - tools/insn: Restore the relative include paths for cross building (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/alternative: Use insn_decode() (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/insn: Add an insn_decode() API (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/insn: Rename insn_decode() to insn_decode_from_regs() (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/paravirt: Add new features for paravirt patching (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/alternative: Support not-feature (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/alternative: Merge include files (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - objtool: Fix error handling for STD/CLD warnings (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/alternatives: Teach text_poke_bp() to emulate RET (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/ftrace: Have ftrace trampolines turn read-only at the end of system boot up (Waiman Long) [2103167
    2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/speculation: Change FILL_RETURN_BUFFER to work with objtool (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - objtool: Add support for intra-function calls (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - objtool: Rework allocating stack_ops on decode (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - objtool: Better handle IRET (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - objtool: Support multiple stack_op per instruction (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - objtool: Make BP scratch register warning more robust (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/kexec: Make relocate_kernel_64.S objtool clean (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - objtool: Introduce validate_return() (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - Makefile: disallow data races on gcc-10 as well (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - objtool: Improve call destination function detection (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/alternatives: Implement a better poke_int3_handler() completion scheme (Waiman Long) [2103167
    2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - lib/: fix Kconfig indentation (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/alternatives: Use INT3_INSN_SIZE (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/kprobes: Fix ordering while text-patching (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/kprobes: Convert to text-patching.h (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/alternative: Shrink text_poke_loc (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/alternative: Remove text_poke_loc::len (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/ftrace: Use text_gen_insn() (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/alternative: Add text_opcode_size() (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/ftrace: Use text_poke() (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/ftrace: Use vmalloc special flag (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/ftrace: Explicitly include vmalloc.h for set_vm_flush_reset_perms() (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/alternatives: Add and use text_gen_insn() helper (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/alternatives, jump_label: Provide better text_poke() batching interface (Waiman Long) [2103167
    2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/asm: Annotate relocate_kernel_{32,64}.c (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86: kprobes: Prohibit probing on instruction which has emulate prefix (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86: Correct misc typos (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901
    CVE-2022-23825}
    - x86/speculation/mds: Apply more accurate check on hypervisor platform (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - objtool: Convert insn type to enum (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - objtool: Track original function across branches (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - objtool: Rename elf_open() to prevent conflict with libelf from elftoolchain (Waiman Long) [2103167
    2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/ftrace: Make enable parameter bool where applicable (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/CPU/AMD: Don't force the CPB cap when running under a hypervisor (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - objtool: Fix function fallthrough detection (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/paravirt: Detect over-sized patching bugs in paravirt_patch_call() (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/cpu/amd: Exclude 32bit only assembler from 64bit build (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/asm: Mark all top level asm statements as .text (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/cpu/bugs: Use __initconst for 'const' init data (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - objtool: Add Direction Flag validation (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - objtool: Rewrite add_ignores() (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/nospec, objtool: Introduce ANNOTATE_IGNORE_ALTERNATIVE (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/ftrace: Fix warning and considate ftrace_jmp_replace() and ftrace_call_replace() (Waiman Long)
    [2103167 2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - kbuild: Disable extra debugging info in .s output (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/CPU/AMD: Set the CPB bit unconditionally on F17h (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/alternatives: Print containing function (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/ftrace: Do not call function graph from dynamic trampolines (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - ftrace: Create new ftrace_internal.h header (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - kprobes/x86: Fix instruction patching corruption when copying more than one RIP-relative instruction
    (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - tracing/Makefile: Fix handling redefinition of CC_FLAGS_FTRACE (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/paravirt: Remove unused paravirt bits (Waiman Long) [2103167 2090229] {CVE-2022-23816 CVE-2022-29900
    CVE-2022-29901 CVE-2022-23825}
    - x86/paravirt: Remove clobbers parameter from paravirt patch functions (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/paravirt: Make paravirt_patch_call() and paravirt_patch_jmp() static (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/l1tf: Fix build error seen if CONFIG_KVM_INTEL is disabled (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - ftrace: Remove unused pointer ftrace_swapper_pid (Waiman Long) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - x86/spec_ctrl: Temporarily remove RHEL specific IBRS code (Waiman Long) [2103167 2090229]
    {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - intel_idle: enable interrupts before C1 on Xeons (Steve Best) [2103167 2090229] {CVE-2022-23816
    CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - KVM: nVMX: Query current VMCS when determining if MSR bitmaps are in use (Vitaly Kuznetsov) [2103167
    2090229] {CVE-2022-23816 CVE-2022-29900 CVE-2022-29901 CVE-2022-23825}
    - af_key: add __GFP_ZERO flag for compose_sadb_supported in function pfkey_register (Xin Long) [2107611
    2075181] {CVE-2022-1353}
    - block-map: add __GFP_ZERO flag for alloc_page in function bio_copy_kern (Ewan D. Milne) [2107627
    2049198] {CVE-2022-0494}
    - net_sched: cls_route: remove from list when handle is 0 (Felix Maurer) [2121817 2116328] {CVE-2022-2588}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-7110.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0494");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2588");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.18.0-372.32.1.0.1.el8_6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2022-7110');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.18';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-4.18.0-372.32.1.0.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-372.32.1.0.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-headers-4.18.0-372.32.1.0.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-tools-4.18.0-372.32.1.0.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-372.32.1.0.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-372.32.1.0.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-372.32.1.0.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-372.32.1.0.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-4.18.0'},
    {'reference':'kernel-abi-stablelists-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-4.18.0'},
    {'reference':'kernel-core-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-4.18.0'},
    {'reference':'kernel-cross-headers-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-debug-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-4.18.0'},
    {'reference':'kernel-debug-core-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-4.18.0'},
    {'reference':'kernel-debug-devel-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-4.18.0'},
    {'reference':'kernel-debug-modules-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-4.18.0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-4.18.0'},
    {'reference':'kernel-devel-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-4.18.0'},
    {'reference':'kernel-headers-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-modules-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-4.18.0'},
    {'reference':'kernel-modules-extra-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-4.18.0'},
    {'reference':'kernel-tools-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-372.32.1.0.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / etc');
}
