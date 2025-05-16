#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-4071.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109156);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2017-15537",
    "CVE-2017-16532",
    "CVE-2017-16646",
    "CVE-2018-1068"
  );

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2018-4071)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2018-4071 advisory.

    - net: cdc_ether: fix divide by 0 on bad descriptors (Bjorn Mork)  [Orabug: 27841392]  {CVE-2017-16649}
    - sysctl: Drop reference added by grab_header in proc_sys_readdir (Zhou Chengming)  [Orabug: 27841944]
    {CVE-2016-9191} {CVE-2016-9191} {CVE-2016-9191}
    - netfilter: ebtables: CONFIG_COMPAT: dont trust userland offsets (Florian Westphal)  [Orabug: 27774012]
    {CVE-2018-1068}
    - KVM: x86: fix singlestepping over syscall (Paolo Bonzini)  [Orabug: 27669904]  {CVE-2017-7518}
    {CVE-2017-7518}
    - fork: fix incorrect fput of ->exe_file causing use-after-free (Eric Biggers)  [Orabug: 27648200]
    {CVE-2017-17052}
    - usb: usbtest: fix NULL pointer dereference (Alan Stern)  [Orabug: 27602322]  {CVE-2017-16532}
    - x86/ia32/syscall: RESTORE_EXTRA_REGS when returning from syscall (Ankur Arora)  [Orabug: 27461990]
    {CVE-2017-5715}
    - x86/ia32/syscall: dont do RESTORE_EXTRA_REGS prematurely (Ankur Arora)  [Orabug: 27461990]
    {CVE-2017-5715}
    - x86/spectre: move microcode check before kernel ibrs flags are set (Daniel Jordan)  [Orabug: 27542331]
    {CVE-2017-5715}
    - Fix typo IBRS_ATT, which should be IBRS_ALL (redux) (Konrad Rzeszutek Wilk)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/spectre_v2: Add spectre_v2_heuristics= (Konrad Rzeszutek Wilk)  [Orabug: 27477743]  {CVE-2017-5715}
    - x86/spectre_v2: Do not disable IBPB when disabling IBRS (Konrad Rzeszutek Wilk)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/scattered: Fix the order. (Konrad Rzeszutek Wilk)  [Orabug: 27477743]  {CVE-2017-5715}
    - x86/spectre: Favor IBRS on Skylake over retpoline (Konrad Rzeszutek Wilk)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/speculation: Fix typo IBRS_ATT, which should be IBRS_ALL (Darren Kenny)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/spectre: Now that we expose 'stbibp' make sure it is correct. (Konrad Rzeszutek Wilk)  [Orabug:
    27477743]  {CVE-2017-5715}
    - x86/cpufeatures: Clean up Spectre v2 related CPUID flags (David Woodhouse)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/speculation: Add basic IBPB (Indirect Branch Prediction Barrier) support (David Woodhouse)  [Orabug:
    27477743]  {CVE-2017-5715}
    - x86/bugs: Drop one 'mitigation' from dmesg (Borislav Petkov)  [Orabug: 27477743]  {CVE-2017-5715}
    - x86/nospec: Fix header guards names (Borislav Petkov)  [Orabug: 27477743]  {CVE-2017-5715}
    - x86/spectre_v2: Dont spam the console with these: (Konrad Rzeszutek Wilk)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/cpufeature: Blacklist SPEC_CTRL/PRED_CMD on early Spectre v2 microcodes (David Woodhouse)  [Orabug:
    27477743]  {CVE-2017-5715}
    - x86/cpu: Keep model defines sorted by model number (Andy Shevchenko)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/pti: Do not enable PTI on CPUs which are not vulnerable to Meltdown (David Woodhouse)  [Orabug:
    27477743]  {CVE-2017-5715}
    - x86/msr: Add definitions for new speculation control MSRs (David Woodhouse)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/cpufeatures: Add AMD feature bits for Speculation Control (David Woodhouse)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/spectre_v2: Print what options are available. (Konrad Rzeszutek Wilk)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/spectre_v2: Add VMEXIT_FILL_RSB instead of RETPOLINE (Konrad Rzeszutek Wilk)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/spectre: If IBRS is enabled disable 'Filling RSB on context switch' (Konrad Rzeszutek Wilk)
    [Orabug: 27477743]  {CVE-2017-5715}
    - KVM: VMX: Allow direct access to MSR_IA32_SPEC_CTRL (Konrad Rzeszutek Wilk)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/spectre_v2: Dont allow {ibrs,ipbp,lfence}_enabled to be toggled if retpoline (Konrad Rzeszutek Wilk)
    [Orabug: 27477743]  {CVE-2017-5715}
    - x86/spectre: Fix retpoline_enabled (Konrad Rzeszutek Wilk)  [Orabug: 27477743]  {CVE-2017-5715}
    - x86/spectre: Update sysctl values if toggled only by set_{ibrs,ibpb}_disabled (Konrad Rzeszutek Wilk)
    [Orabug: 27477743]  {CVE-2017-5715}
    - retpoline/module: Taint kernel for missing retpoline in module (Andi Kleen)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/retpoline: Fill RSB on context switch for affected CPUs (David Woodhouse)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/retpoline: Optimize inline assembler for vmexit_fill_RSB (Andi Kleen)  [Orabug: 27477743]
    {CVE-2017-5715}
    - kprobes/x86: Disable optimizing on the function jumps to indirect thunk (Masami Hiramatsu)  [Orabug:
    27477743]  {CVE-2017-5715}
    - kprobes/x86: Blacklist indirect thunk functions for kprobes (Masami Hiramatsu)  [Orabug: 27477743]
    {CVE-2017-5715}
    - retpoline: Introduce start/end markers of indirect thunk (Masami Hiramatsu)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/mce: Make machine check speculation protected (Thomas Gleixner)  [Orabug: 27477743]  {CVE-2017-5715}
    - kbuild: modversions for EXPORT_SYMBOL() for asm (Nicholas Piggin)  [Orabug: 27477743]  {CVE-2017-5715}
    - x86/retpoline: Add LFENCE to the retpoline/RSB filling RSB macros (Tom Lendacky)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/retpoline: Remove compile time warning (Thomas Gleixner)  [Orabug: 27477743]  {CVE-2017-5715}
    - x86/retpoline: Fill return stack buffer on vmexit (David Woodhouse)  [Orabug: 27477743]  {CVE-2017-5715}
    - x86/retpoline/irq32: Convert assembler indirect jumps (Andi Kleen)  [Orabug: 27477743]  {CVE-2017-5715}
    - x86/retpoline/checksum32: Convert assembler indirect jumps (David Woodhouse)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/retpoline/xen: Convert Xen hypercall indirect jumps (David Woodhouse)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/retpoline/hyperv: Convert assembler indirect jumps (David Woodhouse)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/retpoline/ftrace: Convert ftrace assembler indirect jumps (David Woodhouse)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/retpoline/entry: Convert entry assembler indirect jumps (David Woodhouse)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/retpoline/crypto: Convert crypto assembler indirect jumps (David Woodhouse)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/spectre_v2: Add disable_ibrs_and_friends (Konrad Rzeszutek Wilk)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/spectre_v2: Figure out if STUFF_RSB macro needs to be used. (Konrad Rzeszutek Wilk)  [Orabug:
    27477743]  {CVE-2017-5715}
    - x86/spectre_v2: Figure out when to use IBRS. (Konrad Rzeszutek Wilk)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/spectre: Add IBRS option. (Konrad Rzeszutek Wilk)  [Orabug: 27477743]  {CVE-2017-5715}
    - x86/spectre: Add boot time option to select Spectre v2 mitigation (David Woodhouse)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/retpoline: Add initial retpoline support (David Woodhouse)  [Orabug: 27477743]  {CVE-2017-5715}
    - kconfig.h: use __is_defined() to check if MODULE is defined (Masahiro Yamada)  [Orabug: 27477743]
    {CVE-2017-5715}
    - EXPORT_SYMBOL() for asm (Al Viro)  [Orabug: 27477743]  {CVE-2017-5715}
    - x86/asm: Make asm/alternative.h safe from assembly (Andy Lutomirski)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/kbuild: enable modversions for symbols exported from asm (Adam Borowski)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/asm: Use register variable to get stack pointer value (Andrey Ryabinin)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/mm/32: Move setup_clear_cpu_cap(X86_FEATURE_PCID) earlier (Andy Lutomirski)  [Orabug: 27477743]
    {CVE-2017-5715}
    - x86/alternatives: Add missing '
    ' at end of ALTERNATIVE inline asm (David Woodhouse)  [Orabug: 27477743]  {CVE-2017-5715}
    - x86/alternatives: Fix optimize_nops() checking (Borislav Petkov)  [Orabug: 27477743]  {CVE-2017-5715}
    - KVM: x86: Add memory barrier on vmcs field lookup (Andrew Honig)   {CVE-2017-5753}
    - KVM: VMX: remove I/O port 0x80 bypass on Intel hosts (Andrew Honig)  [Orabug: 27206805]
    {CVE-2017-1000407} {CVE-2017-1000407}
    - x86/fpu: Dont let userspace set bogus xcomp_bv (Tim Tianyang Chen)  [Orabug: 27050688]  {CVE-2017-15537}
    - sctp: do not peel off an assoc from one netns to another one (Xin Long)  [Orabug: 27386997]
    {CVE-2017-15115}
    - media: dib0700: fix invalid dvb_detach argument (Andrey Konovalov)  [Orabug: 27215141]  {CVE-2017-16646}
    - Sanitize 'move_pages()' permission checks (Linus Torvalds)  [Orabug: 27364683]  {CVE-2017-14140}
    - assoc_array: Fix a buggy node-splitting case (David Howells)  [Orabug: 27364588]  {CVE-2017-12193}
    {CVE-2017-12193}
    - net: ipv4: fix for a race condition in raw_sendmsg (Mohamed Ghannam)  [Orabug: 27390679]
    {CVE-2017-17712}
    - x86/pti/efi: broken conversion from efi to kernel page table (Pavel Tatashin)  [Orabug: 27378516]
    [Orabug: 27333760]  {CVE-2017-5754}
    - x86/spec_ctrl: Add missing 'lfence' when IBRS is not supported. (Konrad Rzeszutek Wilk)  [Orabug:
    27344012]  {CVE-2017-5715}
    - x86/entry_64: TRACE_IRQS_OFF before re-enabling. (Jamie Iles)  [Orabug: 27344012]  {CVE-2017-5715}
    - ptrace: remove unlocked RCU dereference. (Jamie Iles)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86/ia32: Adds code hygiene for 32bit SYSCALL instruction entry. (Konrad Rzeszutek Wilk)  [Orabug:
    27344012]  {CVE-2017-5715}
    - x86/ia32: dont save registers on audit call (Konrad Rzeszutek Wilk)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86/spec/ia32: Sprinkle IBRS and RSB at the 32-bit SYSCALL (Konrad Rzeszutek Wilk)  [Orabug: 27344012]
    {CVE-2017-5715}
    - x86/ia32: Move STUFF_RSB And ENABLE_IBRS (Konrad Rzeszutek Wilk)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86/spec: Always set IBRS to guest value on VMENTER and host on VMEXIT. (Konrad Rzeszutek Wilk)
    [Orabug: 27365575]  {CVE-2017-5715}
    - x86/ia32: save and clear registers on syscall. (Jamie Iles)  [Orabug: 27365431]  {CVE-2017-5754}
    - pti: Rename X86_FEATURE_KAISER to X86_FEATURE_PTI (Pavel Tatashin)  [Orabug: 27333760]  {CVE-2017-5754}
    - Re-introduce clearing of r12-15, rbp, rbx (Kris Van Hees)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86: more ibrs/pti fixes (Pavel Tatashin)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/spec: Actually do the check for in_use on ENABLE_IBRS (Konrad Rzeszutek Wilk)  [Orabug: 27344012]
    {CVE-2017-5715}
    - kvm: svm: Expose the CPUID.0x80000008 ebx flag. (Konrad Rzeszutek Wilk)  [Orabug: 27344012]
    {CVE-2017-5715}
    - x86/spec_ctrl: Provide the sysfs version of the ibrs_enabled (Konrad Rzeszutek Wilk)  [Orabug: 27344012]
    {CVE-2017-5715}
    - x86: Use better #define for FEATURE_ENABLE_IBRS and 0 (Konrad Rzeszutek Wilk)  [Orabug: 27344012]
    {CVE-2017-5715}
    - x86: Instead of 0x2, 0x4, and 0x1 use #defines. (Konrad Rzeszutek Wilk)  [Orabug: 27344012]
    {CVE-2017-5715}
    - kpti: Disable when running under Xen PV (Konrad Rzeszutek Wilk)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86: Dont ENABLE_IBRS in nmi when we are still running on user cr3 (Konrad Rzeszutek Wilk)  [Orabug:
    27344012]  {CVE-2017-5715}
    - x86/enter: Use IBRS on syscall and interrupts - fix ia32 path (Konrad Rzeszutek Wilk)  [Orabug:
    27344012]  {CVE-2017-5715}
    - x86: Fix spectre/kpti integration (Konrad Rzeszutek Wilk)  [Orabug: 27333760]  {CVE-2017-5754}
    - PTI: unbreak EFI old_memmap (Jiri Kosina)  [Orabug: 27333760]  {CVE-2017-5754}
    - KAISER KABI tweaks. (Martin K. Petersen)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/ldt: fix crash in ldt freeing. (Jamie Iles)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/entry: Define 'cpu_current_top_of_stack' for 64-bit code (Denys Vlasenko)  [Orabug: 27333760]
    {CVE-2017-5754}
    - x86/entry: Remove unused 'kernel_stack' per-cpu variable (Denys Vlasenko)  [Orabug: 27333760]
    {CVE-2017-5754}
    - x86/entry: Stop using PER_CPU_VAR(kernel_stack) (Denys Vlasenko)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: Set _PAGE_NX only if supported (Guenter Roeck)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/vdso: Get pvclock data from the vvar VMA instead of the fixmap (Andy Lutomirski)  [Orabug: 27333760]
    {CVE-2017-5754}
    - KPTI: Report when enabled (Kees Cook)  [Orabug: 27333760]  {CVE-2017-5754}
    - KPTI: Rename to PAGE_TABLE_ISOLATION (Kees Cook)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/kaiser: Move feature detection up (Borislav Petkov)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/kaiser: Reenable PARAVIRT (Borislav Petkov)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/paravirt: Dont patch flush_tlb_single (Thomas Gleixner)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: kaiser_flush_tlb_on_return_to_user() check PCID (Hugh Dickins)  [Orabug: 27333760]
    {CVE-2017-5754}
    - kaiser: asm/tlbflush.h handle noPGE at lower level (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: drop is_atomic arg to kaiser_pagetable_walk() (Hugh Dickins)  [Orabug: 27333760]
    {CVE-2017-5754}
    - kaiser: use ALTERNATIVE instead of x86_cr3_pcid_noflush (Hugh Dickins)  [Orabug: 27333760]
    {CVE-2017-5754}
    - x86/kaiser: Check boottime cmdline params (Borislav Petkov)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/kaiser: Rename and simplify X86_FEATURE_KAISER handling (Borislav Petkov)  [Orabug: 27333760]
    {CVE-2017-5754}
    - kaiser: add 'nokaiser' boot option, using ALTERNATIVE (Hugh Dickins)  [Orabug: 27333760]
    {CVE-2017-5754}
    - kaiser: fix unlikely error in alloc_ldt_struct() (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: _pgd_alloc() without __GFP_REPEAT to avoid stalls (Hugh Dickins)  [Orabug: 27333760]
    {CVE-2017-5754}
    - kaiser: paranoid_entry pass cr3 need to paranoid_exit (Hugh Dickins)  [Orabug: 27333760]
    {CVE-2017-5754}
    - kaiser: x86_cr3_pcid_noflush and x86_cr3_pcid_user (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: PCID 0 for kernel and 128 for user (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: load_new_mm_cr3() let SWITCH_USER_CR3 flush user (Hugh Dickins)  [Orabug: 27333760]
    {CVE-2017-5754}
    - kaiser: enhanced by kernel and user PCIDs (Dave Hansen)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: vmstat show NR_KAISERTABLE as nr_overhead (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: delete KAISER_REAL_SWITCH option (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: name that 0x1000 KAISER_SHADOW_PGD_OFFSET (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: cleanups while trying for gold link (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: kaiser_remove_mapping() move along the pgd (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: tidied up kaiser_add/remove_mapping slightly (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: tidied up asm/kaiser.h somewhat (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: ENOMEM if kaiser_pagetable_walk() NULL (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: fix perf crashes (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: fix regs to do_nmi() ifndef CONFIG_KAISER (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: KAISER depends on SMP (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: fix build and FIXME in alloc_ldt_struct() (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: stack map PAGE_SIZE at THREAD_SIZE-PAGE_SIZE (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: do not set _PAGE_NX on pgd_none (Hugh Dickins)  [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: merged update (Dave Hansen)  [Orabug: 27333760]  {CVE-2017-5754}
    - KAISER: Kernel Address Isolation (Richard Fellner)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/boot: Add early cmdline parsing for options with arguments (Tom Lendacky)  [Orabug: 27333760]
    {CVE-2017-5754}
    - x86/mm/64: Fix reboot interaction with CR4.PCIDE (Andy Lutomirski)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/mm: Enable CR4.PCIDE on supported systems (Andy Lutomirski)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/mm: Add the 'nopcid' boot option to turn off PCID (Andy Lutomirski)  [Orabug: 27333760]
    {CVE-2017-5754}
    - x86/mm: Disable PCID on 32-bit kernels (Andy Lutomirski)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/mm: Remove the UP asm/tlbflush.h code, always use the (formerly) SMP code (Andy Lutomirski)
    [Orabug: 27333760]  {CVE-2017-5754}
    - x86/mm: Reimplement flush_tlb_page() using flush_tlb_mm_range() (Andy Lutomirski)  [Orabug: 27333760]
    {CVE-2017-5754}
    - x86/mm: Make flush_tlb_mm_range() more predictable (Andy Lutomirski)  [Orabug: 27333760]
    {CVE-2017-5754}
    - x86/mm: Remove flush_tlb() and flush_tlb_current_task() (Andy Lutomirski)  [Orabug: 27333760]
    {CVE-2017-5754}
    - x86/vm86/32: Switch to flush_tlb_mm_range() in mark_screen_rdonly() (Andy Lutomirski)  [Orabug:
    27333760]  {CVE-2017-5754}
    - x86/irq: Do not substract irq_tlb_count from irq_call_count (Aaron Lu)  [Orabug: 27333760]
    {CVE-2017-5754}
    - sched/core: Idle_task_exit() shouldnt use switch_mm_irqs_off() (Andy Lutomirski)  [Orabug: 27333760]
    {CVE-2017-5754}
    - ARM: Hide finish_arch_post_lock_switch() from modules (Steven Rostedt)  [Orabug: 27333760]
    {CVE-2017-5754}
    - x86/mm, sched/core: Turn off IRQs in switch_mm() (Andy Lutomirski)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/mm, sched/core: Uninline switch_mm() (Andy Lutomirski)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/mm: Build arch/x86/mm/tlb.c even on !SMP (Andy Lutomirski)  [Orabug: 27333760]  {CVE-2017-5754}
    - sched/core: Add switch_mm_irqs_off() and use it in the scheduler (Andy Lutomirski)  [Orabug: 27333760]
    {CVE-2017-5754}
    - mm/mmu_context, sched/core: Fix mmu_context.h assumption (Ingo Molnar)  [Orabug: 27333760]
    {CVE-2017-5754}
    - x86/mm: If INVPCID is available, use it to flush global mappings (Andy Lutomirski)  [Orabug: 27333760]
    {CVE-2017-5754}
    - x86/mm: Add a 'noinvpcid' boot option to turn off INVPCID (Andy Lutomirski)  [Orabug: 27333760]
    {CVE-2017-5754}
    - x86/mm: Fix INVPCID asm constraint (Borislav Petkov)  [Orabug: 27333760]  {CVE-2017-5754}
    - x86/mm: Add INVPCID helpers (Andy Lutomirski)  [Orabug: 27333760]  {CVE-2017-5754}
    - kABI: Revert kABI: Make the boot_cpu_data look normal (Konrad Rzeszutek Wilk)  [Orabug: 27344012]
    {CVE-2017-5715}
    - userns: prevent speculative execution (Elena Reshetova)  [Orabug: 27340445]  {CVE-2017-5753}
    - udf: prevent speculative execution (Elena Reshetova)  [Orabug: 27340445]  {CVE-2017-5753}
    - net: mpls: prevent speculative execution (Elena Reshetova)  [Orabug: 27340445]  {CVE-2017-5753}
    - fs: prevent speculative execution (Elena Reshetova)  [Orabug: 27340445]  {CVE-2017-5753}
    - ipv6: prevent speculative execution (Elena Reshetova)  [Orabug: 27340445]  {CVE-2017-5753}
    - ipv4: prevent speculative execution (Elena Reshetova)  [Orabug: 27340445]  {CVE-2017-5753}
    - Thermal/int340x: prevent speculative execution (Elena Reshetova)  [Orabug: 27340445]  {CVE-2017-5753}
    - cw1200: prevent speculative execution (Elena Reshetova)  [Orabug: 27340445]  {CVE-2017-5753}
    - qla2xxx: prevent speculative execution (Elena Reshetova)  [Orabug: 27340445]  {CVE-2017-5753}
    - p54: prevent speculative execution (Elena Reshetova)  [Orabug: 27340445]  {CVE-2017-5753}
    - carl9170: prevent speculative execution (Elena Reshetova)  [Orabug: 27340445]  {CVE-2017-5753}
    - uvcvideo: prevent speculative execution (Elena Reshetova)  [Orabug: 27340445]  {CVE-2017-5753}
    - bpf: prevent speculative execution in eBPF interpreter (Elena Reshetova)  [Orabug: 27340445]
    {CVE-2017-5753}
    - locking/barriers: introduce new observable speculation barrier (Elena Reshetova)  [Orabug: 27340445]
    {CVE-2017-5753}
    - x86/cpu/AMD: Remove now unused definition of MFENCE_RDTSC feature (Elena Reshetova)  [Orabug: 27340445]
    {CVE-2017-5753}
    - x86/cpu/AMD: Make the LFENCE instruction serialized (Elena Reshetova)  [Orabug: 27340445]
    {CVE-2017-5753}
    - kABI: Make the boot_cpu_data look normal. (Konrad Rzeszutek Wilk)  [Orabug: 27344012]  {CVE-2017-5715}
    - kernel.spec: Require the new microcode_ctl. (Konrad Rzeszutek Wilk)  [Orabug: 27344012]  {CVE-2017-5715}
    {CVE-2017-5715}
    - x86/microcode/AMD: Add support for fam17h microcode loading (Tom Lendacky)  [Orabug: 27344012]
    {CVE-2017-5715}
    - x86/spec_ctrl: Disable if running as Xen PV guest. (Konrad Rzeszutek Wilk)  [Orabug: 27344012]
    {CVE-2017-5715}
    - Set IBPB when running a different VCPU (Dave Hansen)  [Orabug: 27344012]  {CVE-2017-5715}
    - Clear the host registers after setbe (Jun Nakajima)  [Orabug: 27344012]  {CVE-2017-5715}
    - Use the ibpb_inuse variable. (Jun Nakajima)  [Orabug: 27344012]  {CVE-2017-5715}
    - KVM: x86: add SPEC_CTRL to MSR and CPUID lists (Andrea Arcangeli)  [Orabug: 27344012]  {CVE-2017-5715}
    - kvm: vmx: add MSR_IA32_SPEC_CTRL and MSR_IA32_PRED_CMD (Paolo Bonzini)  [Orabug: 27344012]
    {CVE-2017-5715}
    - Use the 'ibrs_inuse' variable. (Jun Nakajima)  [Orabug: 27344012]  {CVE-2017-5715}
    - kvm: svm: add MSR_IA32_SPEC_CTRL and MSR_IA32_PRED_CMD (Andrea Arcangeli)  [Orabug: 27344012]
    {CVE-2017-5715}
    - x86/svm: Set IBPB when running a different VCPU (Paolo Bonzini)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86/kvm: Pad RSB on VM transition (Tim Chen)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86/cpu/AMD: Add speculative control support for AMD (Tom Lendacky)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86/microcode: Recheck IBRS and IBPB feature on microcode reload (Tim Chen)  [Orabug: 27344012]
    {CVE-2017-5715}
    - x86: Move IBRS/IBPB feature detection to scattered.c (Tim Chen)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86/spec_ctrl: Add lock to serialize changes to ibrs and ibpb control (Tim Chen)  [Orabug: 27344012]
    {CVE-2017-5715}
    - x86/spec_ctrl: Add sysctl knobs to enable/disable SPEC_CTRL feature (Konrad Rzeszutek Wilk)  [Orabug:
    27344012]  {CVE-2017-5715}
    - x86/kvm: clear registers on VM exit (Tom Lendacky)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86/kvm: Set IBPB when switching VM (Tim Chen)  [Orabug: 27344012]  {CVE-2017-5715}
    - *INCOMPLETE* x86/syscall: Clear unused extra registers on syscall entrance (Konrad Rzeszutek Wilk)
    [Orabug: 27344012]  {CVE-2017-5715}
    - x86/entry: Stuff RSB for entry to kernel for non-SMEP platform (Konrad Rzeszutek Wilk)  [Orabug:
    27344012]  {CVE-2017-5715}
    - x86/mm: Only set IBPB when the new thread cannot ptrace current thread (Konrad Rzeszutek Wilk)  [Orabug:
    27344012]  {CVE-2017-5715}
    - x86/mm: Set IBPB upon context switch (Tim Chen)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86/idle: Disable IBRS when offlining cpu and re-enable on wakeup (Tim Chen)  [Orabug: 27344012]
    {CVE-2017-5715}
    - x86/idle: Disable IBRS entering idle and enable it on wakeup (Tim Chen)  [Orabug: 27344012]
    {CVE-2017-5715}
    - x86/spec_ctrl: save IBRS MSR value in paranoid_entry (Andrea Arcangeli)  [Orabug: 27344012]
    {CVE-2017-5715}
    - *Scaffolding* x86/spec_ctrl: Add sysctl knobs to enable/disable SPEC_CTRL feature (Tim Chen)  [Orabug:
    27344012]  {CVE-2017-5715}
    - x86/enter: Use IBRS on syscall and interrupts (Tim Chen)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86: Add macro that does not save rax, rcx, rdx on stack to disable IBRS (Tim Chen)  [Orabug: 27344012]
    {CVE-2017-5715}
    - x86/enter: MACROS to set/clear IBRS and set IBP (Tim Chen)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86/feature: Report presence of IBPB and IBRS control (Tim Chen)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86: Add STIBP feature enumeration (Konrad Rzeszutek Wilk)  [Orabug: 27344012]  {CVE-2017-5715}
    - x86/cpufeature: Add X86_FEATURE_IA32_ARCH_CAPS and X86_FEATURE_IBRS_ATT (Konrad Rzeszutek Wilk)
    [Orabug: 27344012]  {CVE-2017-5715}
    - x86/feature: Enable the x86 feature to control (Tim Chen)  [Orabug: 27344012]  {CVE-2017-5715}
    - dccp: CVE-2017-8824: use-after-free in DCCP code (Mohamed Ghannam)  [Orabug: 27290292]  {CVE-2017-8824}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-4071.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6 / 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.1.12-124.14.1.el6uek', '4.1.12-124.14.1.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-4071');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.1';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-4.1.12-124.14.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.14.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.14.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.14.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.14.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.14.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'},
    {'reference':'kernel-uek-4.1.12-124.14.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.14.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.14.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.14.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.14.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.14.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
