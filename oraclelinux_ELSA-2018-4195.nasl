#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-4195.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111725);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/26");

  script_cve_id("CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5391");

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel (ELSA-2018-4195)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2018-4195 advisory.

    - ipv4: frags: handle possible skb truesize change (Eric Dumazet)  [Orabug: 28481663]  {CVE-2018-5391}
    - inet: frag: enforce memory limits earlier (Eric Dumazet)  [Orabug: 28481663]  {CVE-2018-5391}
    - x86/mm/kmmio: Make the tracer robust against L1TF (Andi Kleen)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/mm/pat: Make set_memory_np() L1TF safe (Andi Kleen)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/speculation/l1tf: Make pmd/pud_mknotpresent() invert (Andi Kleen)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/speculation/l1tf: Invert all not present mappings (Andi Kleen)  [Orabug: 28442418]  {CVE-2018-3620}
    - cpu/hotplug: Fix SMT supported evaluation (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - KVM: VMX: Tell the nested hypervisor to skip L1D flush on vmentry (Paolo Bonzini)  [Orabug: 28442418]
    {CVE-2018-3646}
    - x86/speculation: Use ARCH_CAPABILITIES to skip L1D flush on vmentry (Paolo Bonzini)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/speculation: Simplify sysfs report of VMX L1TF vulnerability (Paolo Bonzini)  [Orabug: 28442418]
    {CVE-2018-3620}
    - Documentation/l1tf: Remove Yonah processors from not vulnerable list (Thomas Gleixner)  [Orabug:
    28442418]  {CVE-2018-3620}
    - x86/KVM/VMX: Dont set l1tf_flush_l1d from vmx_handle_external_intr() (Nicolai Stange)  [Orabug:
    28442418]  {CVE-2018-3646}
    - x86/irq: Let interrupt handlers set kvm_cpu_l1tf_flush_l1d (Nicolai Stange)  [Orabug: 28442418]
    {CVE-2018-3646}
    - x86: Dont include linux/irq.h from asm/hardirq.h (Nicolai Stange)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/KVM/VMX: Introduce per-host-cpu analogue of l1tf_flush_l1d (Nicolai Stange)  [Orabug: 28442418]
    {CVE-2018-3646}
    - x86/KVM/VMX: Move the l1tf_flush_l1d test to vmx_l1d_flush() (Nicolai Stange)  [Orabug: 28442418]
    {CVE-2018-3646}
    - x86/KVM/VMX: Replace 'vmx_l1d_flush_always' with 'vmx_l1d_flush_cond' (Nicolai Stange)  [Orabug:
    28442418]  {CVE-2018-3646}
    - x86/KVM/VMX: Dont set l1tf_flush_l1d to true from vmx_l1d_flush() (Nicolai Stange)  [Orabug: 28442418]
    {CVE-2018-3646}
    - KVM: VMX: support MSR_IA32_ARCH_CAPABILITIES as a feature MSR (Paolo Bonzini)  [Orabug: 28442418]
    {CVE-2018-3646}
    - cpu/hotplug: detect SMT disabled by BIOS (Josh Poimboeuf)  [Orabug: 28442418]  {CVE-2018-3620}
    - Documentation/l1tf: Fix typos (Tony Luck)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/KVM/VMX: Initialize the vmx_l1d_flush_pages content (Nicolai Stange)  [Orabug: 28442418]
    {CVE-2018-3646}
    - x86/speculation/l1tf: Unbreak !__HAVE_ARCH_PFN_MODIFY_ALLOWED architectures (Jiri Kosina)  [Orabug:
    28442418]  {CVE-2018-3620}
    - Documentation: Add section about CPU vulnerabilities (Thomas Gleixner)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/bugs, kvm: Introduce boot-time control of L1TF mitigations (Jiri Kosina)  [Orabug: 28442418]
    {CVE-2018-3646}
    - cpu/hotplug: Set CPU_SMT_NOT_SUPPORTED early (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - cpu/hotplug: Expose SMT control init function (Jiri Kosina)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/kvm: Allow runtime control of L1D flush (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3646}
    - x86/kvm: Serialize L1D flush parameter setter (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3646}
    - x86/kvm: Add static key for flush always (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3646}
    - x86/kvm: Move l1tf setup function (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3646}
    - x86/l1tf: Handle EPT disabled state proper (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/kvm: Drop L1TF MSR list approach (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3646}
    - x86/litf: Introduce vmx status variable (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - cpu/hotplug: Online siblings when SMT control is turned on (Thomas Gleixner)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/KVM/VMX: Use MSR save list for IA32_FLUSH_CMD if required (Konrad Rzeszutek Wilk)  [Orabug:
    28442418]  {CVE-2018-3646}
    - x86/KVM/VMX: Extend add_atomic_switch_msr() to allow VMENTER only MSRs (Konrad Rzeszutek Wilk)  [Orabug:
    28442418]  {CVE-2018-3646}
    - x86/KVM/VMX: Separate the VMX AUTOLOAD guest/host number accounting (Konrad Rzeszutek Wilk)  [Orabug:
    28442418]  {CVE-2018-3646}
    - x86/KVM/VMX: Add find_msr() helper function (Konrad Rzeszutek Wilk)  [Orabug: 28442418]  {CVE-2018-3646}
    - x86/KVM/VMX: Split the VMX MSR LOAD structures to have an host/guest numbers (Konrad Rzeszutek Wilk)
    [Orabug: 28442418]  {CVE-2018-3646}
    - x86/KVM/VMX: Add L1D flush logic (Paolo Bonzini)  [Orabug: 28442418]  {CVE-2018-3646}
    - x86/KVM/VMX: Add L1D MSR based flush (Paolo Bonzini)  [Orabug: 28442418]  {CVE-2018-3646}
    - x86/KVM/VMX: Add L1D flush algorithm (Paolo Bonzini)  [Orabug: 28442418]  {CVE-2018-3646}
    - x86/KVM/VMX: Add module argument for L1TF mitigation (Konrad Rzeszutek Wilk)  [Orabug: 28442418]
    {CVE-2018-3646} {CVE-2018-3646}
    - x86/KVM: Warn user if KVM is loaded SMT and L1TF CPU bug being present (Konrad Rzeszutek Wilk)  [Orabug:
    28442418]  {CVE-2018-3646}
    - KVM: X86: Provide a capability to disable PAUSE intercepts (Wanpeng Li)  [Orabug: 28442418]
    {CVE-2018-3646}
    - KVM: X86: Provide a capability to disable HLT intercepts (Wanpeng Li)  [Orabug: 28442418]
    {CVE-2018-3646}
    - KVM: X86: Provide a capability to disable MWAIT intercepts (Wanpeng Li)  [Orabug: 28442418]
    {CVE-2018-3646}
    - cpu/hotplug: Boot HT siblings at least once (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - Revert 'x86/apic: Ignore secondary threads if nosmt=force' (Thomas Gleixner)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/speculation/l1tf: Fix up pte->pfn conversion for PAE (Michal Hocko)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/speculation/l1tf: Protect PAE swap entries against L1TF (Vlastimil Babka)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/CPU/AMD: Move TOPOEXT reenablement before reading smp_num_siblings (Borislav Petkov)  [Orabug:
    28442418]  {CVE-2018-3620}
    - x86/cpufeatures: Add detection of L1D cache flush support. (Konrad Rzeszutek Wilk)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/speculation/l1tf: Extend 64bit swap file size limit (Vlastimil Babka)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/apic: Ignore secondary threads if nosmt=force (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/cpu/AMD: Evaluate smp_num_siblings early (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/CPU/AMD: Do not check CPUID max ext level before parsing SMP info (Borislav Petkov)  [Orabug:
    28442418]  {CVE-2018-3620}
    - x86/cpu/intel: Evaluate smp_num_siblings early (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/cpu/topology: Provide detect_extended_topology_early() (Thomas Gleixner)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/cpu/common: Provide detect_ht_early() (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/cpu/AMD: Remove the pointless detect_ht() call (Thomas Gleixner)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/cpu: Remove the pointless CPU printout (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - cpu/hotplug: Provide knobs to control SMT (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - cpu/hotplug: Split do_cpu_down() (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - cpu/hotplug: Make bringup/teardown of smp threads symmetric (Thomas Gleixner)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/topology: Provide topology_smt_supported() (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/smp: Provide topology_is_primary_thread() (Thomas Gleixner)  [Orabug: 28442418]  {CVE-2018-3620}
    - sched/smt: Update sched_smt_present at runtime (Peter Zijlstra)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/bugs: Move the l1tf function and define pr_fmt properly (Konrad Rzeszutek Wilk)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/speculation/l1tf: Limit swap file size to MAX_PA/2 (Andi Klein)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/speculation/l1tf: Disallow non privileged high MMIO PROT_NONE mappings (Andi Kleen)  [Orabug:
    28442418]  {CVE-2018-3620}
    - x86/speculation/l1tf: Add sysfs reporting for l1tf (Andi Klein)  [Orabug: 28442418]  {CVE-2018-3620}
    - x86/speculation/l1tf: Make sure the first page is always reserved (Andi Klein)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/speculation/l1tf: Protect PROT_NONE PTEs against speculation (Andi Klein)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/speculation/l1tf: Protect swap entries against L1TF (Linus Torvalds)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/speculation/l1tf: Change order of offset/type in swap entry (Linus Torvalds)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/speculation/l1tf: Increase 32bit PAE __PHYSICAL_PAGE_SHIFT (Andi Klein)  [Orabug: 28442418]
    {CVE-2018-3620}
    - x86/mm: Limit mmap() of /dev/mem to valid physical addresses (Craig Bergstrom)  [Orabug: 28442418]
    {CVE-2018-3620} {CVE-2018-3620}
    - x86/mm: Prevent non-MAP_FIXED mapping across DEFAULT_MAP_WINDOW border (Kirill A. Shutemov)  [Orabug:
    28442418]  {CVE-2018-3620} {CVE-2018-3620}
    - tcp: add tcp_ooo_try_coalesce() helper (Eric Dumazet)  [Orabug: 28453849]  {CVE-2018-5390}
    - tcp: call tcp_drop() from tcp_data_queue_ofo() (Eric Dumazet)  [Orabug: 28453849]  {CVE-2018-5390}
    - tcp: detect malicious patterns in tcp_collapse_ofo_queue() (Eric Dumazet)  [Orabug: 28453849]
    {CVE-2018-5390}
    - tcp: avoid collapses in tcp_prune_queue() if possible (Eric Dumazet)  [Orabug: 28453849]
    {CVE-2018-5390}
    - tcp: free batches of packets in tcp_prune_ofo_queue() (Eric Dumazet)  [Orabug: 28453849]
    {CVE-2018-5390}
    - socket: close race condition between sock_close() and sockfs_setattr() (Cong Wang)  [Orabug: 28312496]
    {CVE-2018-12232}
    - jfs: Fix inconsistency between memory allocation and ea_buf->max_size (Shankara Pailoor)  [Orabug:
    28312514]  {CVE-2018-12233}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-4195.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3646");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.14.35-1818.1.6.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-4195');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-4.14.35-1818.1.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.14.35'},
    {'reference':'kernel-uek-debug-4.14.35-1818.1.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.14.35'},
    {'reference':'kernel-uek-debug-devel-4.14.35-1818.1.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.14.35'},
    {'reference':'kernel-uek-devel-4.14.35-1818.1.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.14.35'},
    {'reference':'kernel-uek-headers-4.14.35-1818.1.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-4.14.35'},
    {'reference':'kernel-uek-tools-4.14.35-1818.1.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-4.14.35'},
    {'reference':'kernel-uek-tools-libs-4.14.35-1818.1.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-4.14.35'},
    {'reference':'kernel-uek-tools-libs-devel-4.14.35-1818.1.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-devel-4.14.35'},
    {'reference':'perf-4.14.35-1818.1.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-4.14.35'},
    {'reference':'python-perf-4.14.35-1818.1.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-4.14.35'},
    {'reference':'kernel-uek-4.14.35-1818.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.14.35'},
    {'reference':'kernel-uek-debug-4.14.35-1818.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.14.35'},
    {'reference':'kernel-uek-debug-devel-4.14.35-1818.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.14.35'},
    {'reference':'kernel-uek-devel-4.14.35-1818.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.14.35'},
    {'reference':'kernel-uek-doc-4.14.35-1818.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.14.35'},
    {'reference':'kernel-uek-headers-4.14.35-1818.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-4.14.35'},
    {'reference':'kernel-uek-tools-4.14.35-1818.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-4.14.35'},
    {'reference':'kernel-uek-tools-libs-4.14.35-1818.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-4.14.35'},
    {'reference':'kernel-uek-tools-libs-devel-4.14.35-1818.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-devel-4.14.35'},
    {'reference':'perf-4.14.35-1818.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-4.14.35'},
    {'reference':'python-perf-4.14.35-1818.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-4.14.35'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
