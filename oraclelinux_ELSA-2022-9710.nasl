##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9710.
##

include('compat.inc');

if (description)
{
  script_id(164136);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2022-2153",
    "CVE-2022-23816",
    "CVE-2022-2588",
    "CVE-2022-21505",
    "CVE-2022-29901"
  );
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel-container (ELSA-2022-9710)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2022-9710 advisory.

    - net_sched: cls_route: remove from list when handle is 0 (Thadeu Lima de Souza Cascardo)  [Orabug:
    34480880]  {CVE-2022-2588}
    - arm64: proton-pack: provide vulnerability file value for RETBleed (James Morse)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - KVM: emulate: do not adjust size of fastop and setcc subroutines (Paolo Bonzini)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/kvm: fix FASTOP_SIZE when return thunks are enabled (Thadeu Lima de Souza Cascardo)  [Orabug:
    34335632]  {CVE-2022-29901} {CVE-2022-23816}
    - x86/entry: Remove UNTRAIN_RET from native_irq_return_ldt (Alexandre Chartre)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/speculation: Disable RRSBA behavior (Pawan Gupta)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/exec: Disable RET on kexec (Konrad Rzeszutek Wilk)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/bugs: do not enable IBPB-on-entry when IBPB is not supported (Thadeu Lima de Souza Cascardo)
    [Orabug: 34335632]  {CVE-2022-29901} {CVE-2022-23816}
    - x86/bugs: Add Cannon lake to RETBleed affected CPU list (Pawan Gupta)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/cpu/amd: Enumerate BTC_NO (Andrew Cooper)  [Orabug: 34335632]  {CVE-2022-29901} {CVE-2022-23816}
    - x86/common: Stamp out the stepping madness (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - KVM: VMX: Prevent RSB underflow before vmenter (Josh Poimboeuf)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/speculation: Fill RSB on vmexit for IBRS (Josh Poimboeuf)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - KVM: VMX: Fix IBRS handling after vmexit (Josh Poimboeuf)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - KVM: VMX: Prevent guest RSB poisoning attacks with eIBRS (Josh Poimboeuf)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - KVM: VMX: Convert launched argument to flags (Josh Poimboeuf)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - KVM: VMX: Flatten __vmx_vcpu_run() (Josh Poimboeuf)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - KVM/VMX: Use TEST %REG,%REG instead of CMP
    /u03/ksharma/errata_processing/work/el7uek6/db_7uek6.ELSA-2022-9710,%REG in vmenter.S (Uros Bizjak)
    [Orabug: 34335632]  {CVE-2022-29901} {CVE-2022-23816}
    - KVM/nVMX: Use __vmx_vcpu_run in nested_vmx_check_vmentry_hw (Uros Bizjak)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/speculation: Remove x86_spec_ctrl_mask (Josh Poimboeuf)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/speculation: Fix SPEC_CTRL write on SMT state change (Josh Poimboeuf)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/speculation: Fix firmware entry SPEC_CTRL handling (Josh Poimboeuf)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/speculation: Fix RSB filling with CONFIG_RETPOLINE=n (Josh Poimboeuf)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/cpu/amd: Add Spectral Chicken (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Add entry UNRET validation (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - kbuild/objtool: Add objtool-vmlinux.o pass (Peter Zijlstra (Intel))  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/bugs: Do IBPB fallback check only once (Josh Poimboeuf)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/bugs: Add retbleed=ibpb (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/xen: Rename SYS* entry points (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Update Retpoline validation (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - intel_idle: Disable IBRS during long idle (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/bugs: Report Intel retbleed vulnerability (Peter Zijlstra (Intel))  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/bugs: Split spectre_v2_select_mitigation() and spectre_v2_user_select_mitigation() (Peter Zijlstra
    (Intel))  [Orabug: 34335632]  {CVE-2022-29901} {CVE-2022-23816}
    - x86/speculation: Add spectre_v2=ibrs option to support Kernel IBRS (Pawan Gupta)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/bugs: Optimize SPEC_CTRL MSR writes (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/entry: Add kernel IBRS implementation (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/bugs: Keep a per-CPU IA32_SPEC_CTRL value (Peter Zijlstra (Intel))  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/bugs: Enable STIBP for JMP2RET (Kim Phillips)  [Orabug: 34335632]  {CVE-2022-29901} {CVE-2022-23816}
    - x86/bugs: Add AMD retbleed= boot parameter (Alexandre Chartre)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/bugs: Report AMD retbleed vulnerability (Peter Zijlstra (Intel))  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86: Add magic AMD return-thunk (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/vmlinux: Use INT3 instead of NOP for linker fill bytes (Kees Cook)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/realmode: build with __DISABLE_EXPORTS (Ankur Arora)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86: Use return-thunk in asm code (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/sev: Avoid using __x86_return_thunk (Kim Phillips)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/vsyscall_emu/64: Don't use RET in vsyscall emulation (Peter Zijlstra (Intel))  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/kvm: Fix SETcc emulation for return thunks (Peter Zijlstra (Intel))  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/bpf: Alternative RET encoding (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/ftrace: Alternative RET encoding (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86,objtool: Create .return_sites (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/mm: elide references to .discard.* from .return_sites (Ankur Arora)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86: Undo return-thunk damage (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/retpoline: Use -mfunction-return (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/retpoline: Swizzle retpoline thunk (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/alternative: Support not-feature (Juergen Gross)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/retpoline: Cleanup some #ifdefery (Peter Zijlstra (Intel))  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86/features: Move RETPOLINE flags to word 11 (Peter Zijlstra (Intel))  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - crypto: x86/poly1305 - Fixup SLS (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901} {CVE-2022-23816}
    - kvm/emulate: Fix SETcc emulation function offsets with SLS (Borislav Petkov)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86: Add straight-line-speculation mitigation (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - x86: Prepare inline-asm for straight-line-speculation (Peter Zijlstra)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86: Prepare asm files for straight-line-speculation (Peter Zijlstra)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - x86/lib/atomic64_386_32: Rename things (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Add straight-line-speculation validation (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Classify symbols (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901} {CVE-2022-23816}
    - objtool: Create reloc sections implicitly (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Add elf_create_reloc() helper (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Rework the elf_rebuild_reloc_section() logic (Peter Zijlstra)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - objtool: Handle per arch retpoline naming (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Correctly handle retpoline thunk calls (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Support retpoline jump detection for vmlinux.o (Josh Poimboeuf)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - objtool: Add 'alt_group' struct (Josh Poimboeuf)  [Orabug: 34335632]  {CVE-2022-29901} {CVE-2022-23816}
    - objtool: Clean up elf_write() condition (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Add support for relocations without addends (Matt Helsley)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - objtool: Rename rela to reloc (Matt Helsley)  [Orabug: 34335632]  {CVE-2022-29901} {CVE-2022-23816}
    - objtool: optimize add_dead_ends for split sections (Sami Tolvanen)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Move the IRET hack into the arch decoder (Miroslav Benes)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Rename elf_read() to elf_open_read() (Ingo Molnar)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Constify 'struct elf *' parameters (Ingo Molnar)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Optimize !vmlinux.o again (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Better handle IRET (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901} {CVE-2022-23816}
    - x86/unwind_hints: define unwind_hint_save, unwind_hint_restore (Ankur Arora)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - objtool: Add abstraction for destination offsets (Raphael Gault)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Fix off-by-one in symbol_by_offset() (Julien Thierry)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Optimize find_rela_by_dest_range() (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Optimize read_sections() (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Optimize find_symbol_by_name() (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Rename find_containing_func() (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Optimize find_symbol_*() and read_symbols() (Peter Zijlstra)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - objtool: Optimize find_section_by_name() (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Optimize find_section_by_index() (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Add a statistics mode (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901} {CVE-2022-23816}
    - objtool: Optimize find_symbol_by_index() (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Rename func_for_each_insn_all() (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Rename func_for_each_insn() (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Introduce validate_return() (Peter Zijlstra)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Improve call destination function detection (Josh Poimboeuf)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - objtool: Fix clang switch table edge case (Josh Poimboeuf)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - objtool: Add relocation check for alternative sections (Josh Poimboeuf)  [Orabug: 34335632]
    {CVE-2022-29901} {CVE-2022-23816}
    - objtool: Add is_static_jump() helper (Josh Poimboeuf)  [Orabug: 34335632]  {CVE-2022-29901}
    {CVE-2022-23816}
    - lockdown: Fix kexec lockdown bypass with ima policy (Eric Snowberg)  [Orabug: 34400675]
    {CVE-2022-21505}
    - KVM: x86: Avoid theoretical NULL pointer dereference in kvm_irq_delivery_to_apic_fast() (Vitaly
    Kuznetsov)  [Orabug: 34323859]  {CVE-2022-2153}
    - KVM: x86: Check lapic_in_kernel() before attempting to set a SynIC irq (Vitaly Kuznetsov)  [Orabug:
    34323859]  {CVE-2022-2153}
    - KVM: Add infrastructure and macro to mark VM as bugged (Sean Christopherson)  [Orabug: 34323859]
    {CVE-2022-2153}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9710.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek-container and / or kernel-uek-container-debug packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29901");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2588");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
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
if (! preg(pattern:"^(7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7 / 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.4.17-2136.310.7.el7', '5.4.17-2136.310.7.el8'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2022-9710');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.4';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-container-5.4.17-2136.310.7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.310.7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'},
    {'reference':'kernel-uek-container-5.4.17-2136.310.7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.310.7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek-container / kernel-uek-container-debug');
}
