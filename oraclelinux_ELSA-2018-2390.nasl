#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-2390.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111724);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2017-0861",
    "CVE-2017-15265",
    "CVE-2018-3620",
    "CVE-2018-3646",
    "CVE-2018-3693",
    "CVE-2018-5390",
    "CVE-2018-7566",
    "CVE-2018-10901",
    "CVE-2018-1000004"
  );
  script_xref(name:"RHSA", value:"2018:2390");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2018-2390)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2018-2390 advisory.

    - [kernel] cpu/hotplug: Enable 'nosmt' as late as possible (Frantisek Hrbata) [1593376] {CVE-2018-3620}
    - [x86] x86/mm: Simplify p[g4um]d_page() macros (Josh Poimboeuf) [1593376] {CVE-2018-3620}
    - [x86] x86/mm: Fix regression with huge pages on PAE (Josh Poimboeuf) [1593376] {CVE-2018-3620}
    - [x86] x86/asm: Fix pud/pmd interfaces to handle large PAT bit (Josh Poimboeuf) [1593376] {CVE-2018-3620}
    - [x86] x86/asm: Add pud/pmd mask interfaces to handle large PAT bit (Josh Poimboeuf) [1593376]
    {CVE-2018-3620}
    - [x86] x86/asm: Move PUD_PAGE macros to page_types.h (Josh Poimboeuf) [1593376] {CVE-2018-3620}
    - [net] tcp: detect malicious patterns in tcp_collapse_ofo_queue() (Florian Westphal) [1611376]
    {CVE-2018-5390}
    - [net] tcp: avoid collapses in tcp_prune_queue() if possible (Florian Westphal) [1611376] {CVE-2018-5390}
    - [net] tcp: free batches of packets in tcp_prune_ofo_queue() (Florian Westphal) [1611376] {CVE-2018-5390}
    - [net] add rb_to_skb() and other rb tree helpers (Florian Westphal) [1611376] {CVE-2018-5390}
    - [net] tcp: fix a stale ooo_last_skb after a replace (Florian Westphal) [1611376] {CVE-2018-5390}
    - [net] tcp: use an RB tree for ooo receive queue (Florian Westphal) [1611376] {CVE-2018-5390}
    - [net] add rbnode to struct sk_buff (Florian Westphal) [1611376] {CVE-2018-5390}
    - [net] tcp: refine tcp_prune_ofo_queue() to not drop all packets (Florian Westphal) [1611376]
    {CVE-2018-5390}
    - [x86] syscall: Fix regression when using the last syscall (process_vm_writev) (Lauro Ramos Venancio)
    [1589032] {CVE-2018-3693}
    - [x86] syscall: Fix regression on strace and stap (Lauro Ramos Venancio) [1589032] {CVE-2018-3693}
    - [kvm] VMX: Fix host GDT.LIMIT corruption (CVE-2018-10301) (Paolo Bonzini) [1601851] {CVE-2018-10901}
    - [x86] Initialize __max_smt_threads to 1 (Waiman Long) [1593376] {CVE-2018-3620}
    - [kernel] cpu/hotplug: detect SMT disabled by BIOS (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] topology: Add topology_max_smt_threads() (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] speculation/l1tf: Fix incorrect error return code in vm_insert_pfn() (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] KVM/VMX: Initialize the vmx_l1d_flush_pages' content (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] kvm: Don't flush L1D cache if VMENTER_L1D_FLUSH_NEVER (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] kvm: Take out the unused nosmt module parameter (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] mm/dump_pagetables: Add a check_l1tf debugfs file (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] l1tf: protect _PAGE_FILE PTEs against speculation for 32-bit PAE (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Protect swap entries aganst L1TF for 32-bit PAE (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] cpu: Make flush_l1d visible in /proc/cpuinfo (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] l1tf: protect _PAGE_FILE PTEs against speculation (Waiman Long) [1593376] {CVE-2018-3620}
    - [Documentation] Add section about CPU vulnerabilities (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] bugs, kvm: Introduce boot-time control of L1TF mitigations (Waiman Long) [1593376] {CVE-2018-3620}
    - [kernel] cpu/hotplug: Set CPU_SMT_NOT_SUPPORTED early (Waiman Long) [1593376] {CVE-2018-3620}
    - [kernel] cpu/hotplug: Expose SMT control init function (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] kvm: Allow runtime control of L1D flush (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] kvm: Serialize L1D flush parameter setter (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] kvm: Move l1tf setup function (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] l1tf: Handle EPT disabled state proper (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] kvm: Drop L1TF MSR list approach (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] litf: Introduce vmx status variable (Waiman Long) [1593376] {CVE-2018-3620}
    - [kernel] cpu/hotplug: Online siblings when SMT control is turned on (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] KVM/VMX: Use MSR save list for IA32_FLUSH_CMD if required (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] KVM/VMX: Extend add_atomic_switch_msr() to allow VMENTER only MSRs (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] KVM/VMX: Separate the VMX AUTOLOAD guest/host number accounting (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] KVM/VMX: Add find_msr() helper function (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] KVM/VMX: Split the VMX MSR LOAD structures to have an host/guest numbers (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] KVM/VMX: Add L1D flush logic (Waiman Long) [1593376] {CVE-2018-3620}
    - [kvm] VMX: Make indirect call speculation safe (Waiman Long) [1593376] {CVE-2018-3620}
    - [kvm] VMX: Enable acknowledge interupt on vmexit (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] KVM/VMX: Add L1D MSR based flush (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] KVM/VMX: Add L1D flush algorithm (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] KVM/VMX: Add module argument for L1TF mitigation (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] KVM: Warn user if KVM is loaded SMT and L1TF CPU bug being present (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [kvm] x86: Introducing kvm_x86_ops VM init/destroy hooks (Waiman Long) [1593376] {CVE-2018-3620}
    - [kernel] cpu/hotplug: Boot HT siblings at least once (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] Revert 'x86/apic: Ignore secondary threads if nosmt=force' (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] speculation/l1tf: Fix up pte->pfn conversion for PAE (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] CPU/AMD: Move TOPOEXT reenablement before reading smp_num_siblings (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] cpufeatures: Add detection of L1D cache flush support. (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] speculation/l1tf: Extend 64bit swap file size limit (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] apic: Ignore secondary threads if nosmt=force (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] cpu/AMD: Evaluate smp_num_siblings early (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] CPU/AMD: Do not check CPUID max ext level before parsing SMP info (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] cpu/intel: Evaluate smp_num_siblings early (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] cpu/topology: Provide detect_extended_topology_early() (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] cpu/common: Provide detect_ht_early() (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] cpu/AMD: Remove the pointless detect_ht() call (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] cpu: Remove the pointless CPU printout (Waiman Long) [1593376] {CVE-2018-3620}
    - [kernel] cpu/hotplug: Provide knobs to control SMT (Waiman Long) [1593376] {CVE-2018-3620}
    - [kernel] cpu/hotplug: Split do_cpu_down() (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] topology: Provide topology_smt_supported() (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] smp: Provide topology_is_primary_thread() (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] bugs: Move the l1tf function and define pr_fmt properly (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] speculation/l1tf: Limit swap file size to MAX_PA/2 (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] speculation/l1tf: Disallow non privileged high MMIO PROT_NONE mappings (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Add sysfs reporting for l1tf (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] speculation/l1tf: Protect PROT_NONE PTEs against speculation (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Protect swap entries against L1TF (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] speculation/l1tf: Change order of offset/type in swap entry (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Increase 32bit PAE __PHYSICAL_PAGE_SHIFT (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] cpu: Fix incorrect vulnerabilities files function prototypes (Waiman Long) [1593376]
    {CVE-2018-3620}
    - [x86] bugs: Export the internal __cpu_bugs variable (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] spec_ctrl: sync with upstream cpu_set_bug_bits() (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] intel-family.h: Add GEMINI_LAKE SOC (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] mm: Fix swap entry comment and macro (Waiman Long) [1593376] {CVE-2018-3620}
    - [x86] mm: Move swap offset/type up in PTE to work around erratum (Waiman Long) [1593376] {CVE-2018-3620}
    - [sound] alsa: pcm: prevent UAF in snd_pcm_info (CVE-2017-0861) (Jaroslav Kysela) [1565188]
    {CVE-2017-0861}
    - [sound] alsa: seq: Fix racy pool initializations (Jaroslav Kysela) [1550176] {CVE-2018-7566}
    - [sound] alsa: seq: Fix use-after-free at creating a port (Jaroslav Kysela) [1503383] {CVE-2017-15265}
    - [sound] alsa: seq: Make ioctls race-free (Jaroslav Kysela) [1537452] {CVE-2018-1000004}
    - [usb] acm: fix the computation of the number of data bits (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [misc] spectre: fix gadgets found by smatch scanner, part 2 (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [x86] kvm/vmx: Remove barrier_nospec() in slot_largepage_idx() (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [kvm] Remove memory alias support (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [misc] spectre: fix gadgets found by smatch scanner (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [sound] alsa: rme9652: Hardening for potential Spectre v1 (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [sound] alsa: opl3: Hardening for potential Spectre v1 (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [sound] alsa: hda: Hardening for potential Spectre v1 (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [sound] alsa: seq: oss: Hardening for potential Spectre v1 (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [sound] alsa: seq: oss: Fix unbalanced use lock for synth MIDI device (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [net] atm: Fix potential Spectre v1 (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [kernel] posix-timers: Protect posix clock array access against speculation (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [kernel] sys.c: fix potential Spectre v1 issue (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [kernel] sched/autogroup: Fix possible Spectre-v1 indexing for sched_prio_to_weight[] (Josh Poimboeuf)
    [1589032] {CVE-2018-3693}
    - [kernel] perf/core: Fix possible Spectre-v1 indexing for ->aux_pages[] (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [ipc] sysvipc/sem: mitigate semnum index against spectre v1 (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [sound] alsa: control: Hardening for potential Spectre v1 (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [media] dvb_ca_en50221: prevent using slot_info for Spectre attacs (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - media] dvb_ca_en50221: sanity check slot number from userspace (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [atm] zatm: Fix potential Spectre v1 (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [x86] perf: Fix possible Spectre-v1 indexing for x86_pmu::event_map() (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [x86] perf: Fix possible Spectre-v1 indexing for hw_perf_event cache_* (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [net] nl80211: Sanitize array index in parse_txq_params (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [include] vfs, fdtable: Prevent bounds-check bypass via speculative execution (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [x86] syscall: Sanitize syscall table de-references under speculation (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [powerpc] Use barrier_nospec in copy_from_user() (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [include] nospec: Introduce barrier_nospec for other arches (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [x86] Introduce barrier_nospec (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [x86] spectre_v1: Disable compiler optimizations over array_index_mask_nospec() (Josh Poimboeuf)
    [1589032] {CVE-2018-3693}
    - [x86] Implement array_index_mask_nospec (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [documentation] Document array_index_nospec (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    dependency (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [include] nospec: Allow index argument to have const-qualified type (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [include] nospec: Kill array_index_nospec_mask_check() (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [include] nospec: Move array_index_nospec() parameter checking into separate macro (Josh Poimboeuf)
    [1589032] {CVE-2018-3693}
    - [include] array_index_nospec: Sanitize speculative array de-references (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [x86] get_user: Use pointer masking to limit speculation (Josh Poimboeuf) [1589032] {CVE-2018-3693}
    - [x86] uaccess: Use __uaccess_begin_nospec() and uaccess_try_nospec (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [x86] Introduce __uaccess_begin_nospec() and uaccess_try_nospec (Josh Poimboeuf) [1589032]
    {CVE-2018-3693}
    - [x86] reorganize SMAP handling in user space accesses (Josh Poimboeuf) [1589032] {CVE-2018-3693}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-2390.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10901");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-7566");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");

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
  var fixed_uptrack_levels = ['2.6.32-754.3.5.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-2390');
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
    {'reference':'kernel-2.6.32-754.3.5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-abi-whitelists-2.6.32-754.3.5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-2.6.32'},
    {'reference':'kernel-debug-2.6.32-754.3.5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-754.3.5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-754.3.5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-754.3.5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-754.3.5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-754.3.5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-754.3.5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.32-754.3.5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-abi-whitelists-2.6.32-754.3.5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-2.6.32'},
    {'reference':'kernel-debug-2.6.32-754.3.5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-754.3.5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-754.3.5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-754.3.5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-754.3.5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-754.3.5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-754.3.5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
