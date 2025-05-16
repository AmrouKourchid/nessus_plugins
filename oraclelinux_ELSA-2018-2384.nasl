#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-2384.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111723);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2017-13215",
    "CVE-2018-3620",
    "CVE-2018-3646",
    "CVE-2018-3693",
    "CVE-2018-5390",
    "CVE-2018-7566",
    "CVE-2018-10675"
  );
  script_xref(name:"RHSA", value:"2018:2384");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2018-2384)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2018-2384 advisory.

    - [kernel] cpu/hotplug: Fix 'online' sysfs entry with 'nosmt' (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [kernel] cpu/hotplug: Enable 'nosmt' as late as possible (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [net] ipv6: fix nospec-related regression in ipv6_addr_prefix() (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3693}
    - [net] tcp: add tcp_ooo_try_coalesce() helper (Paolo Abeni) [1611368 1611369] {CVE-2018-5390}
    - [net] tcp: call tcp_drop() from tcp_data_queue_ofo() (Paolo Abeni) [1611368 1611369] {CVE-2018-5390}
    - [net] tcp: detect malicious patterns in tcp_collapse_ofo_queue() (Paolo Abeni) [1611368 1611369]
    {CVE-2018-5390}
    - [net] tcp: avoid collapses in tcp_prune_queue() if possible (Paolo Abeni) [1611368 1611369]
    {CVE-2018-5390}
    - [net] tcp: free batches of packets in tcp_prune_ofo_queue() (Paolo Abeni) [1611368 1611369]
    {CVE-2018-5390}
    - [net] net: add rb_to_skb() and other rb tree helpers (Paolo Abeni) [1611368 1611369] {CVE-2018-5390}
    - [net] tcp: fix a stale ooo_last_skb after a replace (Paolo Abeni) [1611368 1611369] {CVE-2018-5390}
    - [net] tcp: use an RB tree for ooo receive queue (Paolo Abeni) [1611368 1611369] {CVE-2018-5390}
    - [net] tcp: refine tcp_prune_ofo_queue() to not drop all packets (Paolo Abeni) [1611368 1611369]
    {CVE-2018-5390}
    - [net] tcp: increment sk_drops for dropped rx packets (Paolo Abeni) [1611368 1611369] {CVE-2018-5390}
    - [x86] x86/syscall: Fix regression when using the last syscall (pkey_free) (Lauro Ramos Venancio)
    [1589033 1589035] {CVE-2018-3693}
    - [kernel] cpu: hotplug: detect SMT disabled by BIOS (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [documentation] l1tf: Fix typos (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] kvm: Remove extra newline in vmentry_l1d_flush sysfs file (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] kvm: vmx: Initialize the vmx_l1d_flush_pages' content (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] speculation: l1tf: Unbreak !__HAVE_ARCH_PFN_MODIFY_ALLOWED architectures (Josh Poimboeuf) [1593383
    1593384] {CVE-2018-3620}
    - [documentation] Add section about CPU vulnerabilities (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] bugs, kvm: introduce boot-time control of L1TF mitigations (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [kernel] cpu: hotplug: Set CPU_SMT_NOT_SUPPORTED early (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [kernel] cpu: hotplug: Expose SMT control init function (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] kvm: Allow runtime control of L1D flush (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] kvm: Serialize L1D flush parameter setter (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] kvm: Add static key for flush always (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] kvm: Move l1tf setup function (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] l1tf: Handle EPT disabled state proper (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] kvm: Drop L1TF MSR list approach (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] litf: Introduce vmx status variable (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] bugs: Make cpu_show_common() static (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] bugs: Concentrate bug reporting into a separate function (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [kernel] cpu: hotplug: Online siblings when SMT control is turned on (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] kvm: vmx: Use MSR save list for IA32_FLUSH_CMD if required (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] kvm: vmx: Extend add_atomic_switch_msr() to allow VMENTER only MSRs (Josh Poimboeuf) [1593383
    1593384] {CVE-2018-3620}
    - [x86] kvm: vmx: Separate the VMX AUTOLOAD guest/host number accounting (Josh Poimboeuf) [1593383
    1593384] {CVE-2018-3620}
    - [x86] kvm: vmx: Add find_msr() helper function (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] kvm: vmx: Split the VMX MSR LOAD structures to have an host/guest numbers (Josh Poimboeuf)
    [1593383 1593384] {CVE-2018-3620}
    - [x86] kvm: mitigation for L1 cache terminal fault vulnerabilities, part 3 (Josh Poimboeuf) [1593383
    1593384] {CVE-2018-3620}
    - [x86] kvm: Warn user if KVM is loaded SMT and L1TF CPU bug being present (Josh Poimboeuf) [1593383
    1593384] {CVE-2018-3620}
    - [kernel] cpu: hotplug: Boot HT siblings at least once, part 2 (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: fix typo in l1tf mitigation string (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] l1tf: protect _PAGE_FILE PTEs against speculation (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] kvm: mitigation for L1 cache terminal fault vulnerabilities, part 2 (Josh Poimboeuf) [1593383
    1593384] {CVE-2018-3620}
    - [kernel] cpu/hotplug: Boot HT siblings at least once (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - Revert 'x86/apic: Ignore secondary threads if nosmt=force' (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Fix up pte->pfn conversion for PAE (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Protect PAE swap entries against L1TF (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] CPU/AMD: Move TOPOEXT reenablement before reading smp_num_siblings (Josh Poimboeuf) [1593383
    1593384] {CVE-2018-3620}
    - [x86] speculation/l1tf: Extend 64bit swap file size limit (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] cpu/AMD: Remove the pointless detect_ht() call (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] bugs: Move the l1tf function and define pr_fmt properly (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [kernel] cpu/hotplug: Provide knobs to control SMT, part 2 (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] topology: Provide topology_smt_supported() (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] smp: Provide topology_is_primary_thread(), part 2 (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] apic: Ignore secondary threads if nosmt=force (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] cpu/AMD: Evaluate smp_num_siblings early (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] CPU/AMD: Do not check CPUID max ext level before parsing SMP info (Josh Poimboeuf) [1593383
    1593384] {CVE-2018-3620}
    - [x86] cpu/intel: Evaluate smp_num_siblings early (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] cpu/topology: Provide detect_extended_topology_early() (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] cpu/common: Provide detect_ht_early() (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] cpu: Remove the pointless CPU printout (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [kernel] cpu/hotplug: Provide knobs to control SMT (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [kernel] cpu/hotplug: Split do_cpu_down() (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] smp: Provide topology_is_primary_thread() (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] CPU: Modify detect_extended_topology() to return result (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] l1tf: fix build for CONFIG_NUMA_BALANCING=n (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] l1tf: sync with latest L1TF patches (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] l1tf: protect _PAGE_NUMA PTEs and PMDs against speculation (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [mm] l1tf: Disallow non privileged high MMIO PROT_NONE mappings (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] l1tf: Report if too much memory for L1TF workaround (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] l1tf: Limit swap file size to MAX_PA/2 (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] l1tf: Add sysfs reporting for l1tf (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] l1tf: Make sure the first page is always reserved (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] l1tf: Protect PROT_NONE PTEs against speculation (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86] l1tf: Protect swap entries against L1TF (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] l1tf: Increase 32bit PAE __PHYSICAL_PAGE_MASK (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] mm: Fix swap entry comment and macro (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] spec_ctrl: sync with upstream cpu_set_bug_bits() (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [x86]  add support for L1D flush MSR (Josh Poimboeuf) [1593383 1593384] {CVE-2018-3620}
    - [x86] kvm: mitigation for L1 cache terminal fault vulnerabilities (Josh Poimboeuf) [1593383 1593384]
    {CVE-2018-3620}
    - [spectre] update Spectre v1 mitigation string (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [spectre] fix hiddev nospec issues (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [x86] syscall: clarify clobbered registers in entry code (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [powerpc] add missing barrier_nospec() in __get_user64_nocheck() (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [spectre] fix gadgets found by smatch scanner (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [alsa] rme9652: Hardening for potential Spectre v1 (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [alsa] hdspm: Hardening for potential Spectre v1 (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [alsa] asihpi: Hardening for potential Spectre v1 (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [alsa] opl3: Hardening for potential Spectre v1 (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [alsa] hda: Hardening for potential Spectre v1 (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [alsa] seq: oss: Hardening for potential Spectre v1 (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [alsa] seq: oss: Fix unbalanced use lock for synth MIDI device (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [net] atm: Fix potential Spectre v1 (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [kernel] time: Protect posix clock array access against speculation (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [kernel] sys.c: fix potential Spectre v1 issue (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [sched] autogroup: Fix possible Spectre-v1 indexing for sched_prio_to_weight[] (Josh Poimboeuf) [1589033
    1589035] {CVE-2018-3690}
    - [perf] core: Fix possible Spectre-v1 indexing for ->aux_pages[] (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [sysvipc] sem: mitigate semnum index against spectre v1 (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [alsa] control: Hardening for potential Spectre v1 (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [usbip] vhci_sysfs: fix potential Spectre v1 (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [media] dvb_ca_en50221: prevent using slot_info for Spectre attacs (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [media] dvb_ca_en50221: sanity check slot number from userspace (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [atm] zatm: Fix potential Spectre v1 (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [x86] kvm: Update spectre-v1 mitigation (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [x86] kvm: Add memory barrier on vmcs field lookup (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [x86] perf/msr: Fix possible Spectre-v1 indexing in the MSR driver (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [x86] perf: Fix possible Spectre-v1 indexing for x86_pmu::event_map() (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [x86] perf: Fix possible Spectre-v1 indexing for hw_perf_event cache_* (Josh Poimboeuf) [1589033
    1589035] {CVE-2018-3690}
    - [net] nl80211: Sanitize array index in parse_txq_params (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [include] vfs, fdtable: Prevent bounds-check bypass via speculative execution (Josh Poimboeuf) [1589033
    1589035] {CVE-2018-3690}
    - [x86] syscall: Sanitize syscall table de-references under speculation (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [powerpc] Use barrier_nospec in copy_from_user() (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [include] nospec: Introduce barrier_nospec for other arches (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [x86] Introduce barrier_nospec (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [x86] spectre_v1: Disable compiler optimizations over array_index_mask_nospec() (Josh Poimboeuf)
    [1589033 1589035] {CVE-2018-3690}
    - [x86] Implement array_index_mask_nospec (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [documentation] Document array_index_nospec (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    dependency (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [include] nospec: Allow index argument to have const-qualified type (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [include] nospec: Kill array_index_nospec_mask_check() (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [include] nospec: Move array_index_nospec() parameter checking into separate macro (Josh Poimboeuf)
    [1589033 1589035] {CVE-2018-3690}
    - [include] array_index_nospec: Sanitize speculative array de-references (Josh Poimboeuf) [1589033
    1589035] {CVE-2018-3690}
    - [x86] get_user: Use pointer masking to limit speculation (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [x86] uaccess: Use __uaccess_begin_nospec() and uaccess_try_nospec (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [x86] Introduce __uaccess_begin_nospec() and uaccess_try_nospec (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [x86] usercopy: Replace open coded stac/clac with __uaccess_{begin, end} (Josh Poimboeuf) [1589033
    1589035] {CVE-2018-3690}
    - [x86] reorganize SMAP handling in user space accesses (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [x86] uaccess: Tell the compiler that uaccess is unlikely to fault (Josh Poimboeuf) [1589033 1589035]
    {CVE-2018-3690}
    - [x86] uaccess: fix sparse errors (Josh Poimboeuf) [1589033 1589035] {CVE-2018-3690}
    - [mm] mempolicy: fix use after free when calling get_mempolicy (Augusto Caringi) [1576759 1576755]
    {CVE-2018-10675}
    - [sound] alsa: seq: Fix racy pool initializations (Jaroslav Kysela) [1550171 1593586 1550169 1535427]
    {CVE-2018-7566}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-2384.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10675");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-7566");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");

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
  var fixed_uptrack_levels = ['3.10.0-862.11.6.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-2384');
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
    {'reference':'kernel-3.10.0-862.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-862.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-862.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-862.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-862.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-862.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-862.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-862.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-862.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-862.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-862.11.6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
