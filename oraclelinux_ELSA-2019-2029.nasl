#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-2029.
##

include('compat.inc');

if (description)
{
  script_id(180763);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2018-7755",
    "CVE-2018-8087",
    "CVE-2018-9363",
    "CVE-2018-9516",
    "CVE-2018-9517",
    "CVE-2018-10853",
    "CVE-2018-13053",
    "CVE-2018-13093",
    "CVE-2018-13094",
    "CVE-2018-13095",
    "CVE-2018-14625",
    "CVE-2018-14734",
    "CVE-2018-15594",
    "CVE-2018-16658",
    "CVE-2018-16885",
    "CVE-2018-18281",
    "CVE-2019-3459",
    "CVE-2019-3460",
    "CVE-2019-3882",
    "CVE-2019-3900",
    "CVE-2019-5489",
    "CVE-2019-7222",
    "CVE-2019-11599",
    "CVE-2019-11810",
    "CVE-2019-11833"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2019-2029)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2019-2029 advisory.

    - [scsi] scsi: megaraid_sas: return error when create DMA pool failed (Tomas Henzl) [1712861]
    {CVE-2019-11810}
    - [net] tcp: enforce tcp_min_snd_mss in tcp_mtu_probing() (Florian Westphal) [1719915] {CVE-2019-11479}
    - [net] tcp: add tcp_min_snd_mss sysctl (Florian Westphal) [1719915] {CVE-2019-11479}
    - [net] tcp: limit payload size of sacked skbs (Florian Westphal) [1719595] {CVE-2019-11477}
    - [net] tcp: pass previous skb to tcp_shifted_skb() (Florian Westphal) [1719595] {CVE-2019-11477}
    - [net] tcp: tcp_fragment() should apply sane memory limits (Florian Westphal) [1719850] {CVE-2019-11478}
    - [mm] mincore.c: make mincore() more conservative (Rafael Aquini) [1664199] {CVE-2019-5489}
    - [kernel] alarmtimer: Prevent overflow for relative nanosleep (Artem Savkov) [1653677] {CVE-2018-13053}
    - [fs] ext4: zero out the unused memory region in the extent tree block (Lukas Czerner) [1715280]
    {CVE-2019-11833}
    - [vhost] vsock: add weight support (Jason Wang) [1702943] {CVE-2019-3900}
    - [vhost] vhost_net: fix possible infinite loop (Jason Wang) [1702943] {CVE-2019-3900}
    - [vhost] introduce vhost_exceeds_weight() (Jason Wang) [1702943] {CVE-2019-3900}
    - [vhost] vhost_net: introduce vhost_exceeds_weight() (Jason Wang) [1702943] {CVE-2019-3900}
    - [vhost] vhost_net: use packet weight for rx handler, too (Jason Wang) [1702943] {CVE-2019-3900}
    - [vhost] vhost-net: set packet weight of tx polling to 2 * vq size (Jason Wang) [1702943] {CVE-2019-3900}
    - [x86] kvm: x86: use correct privilege level for sgdt/sidt/fxsave/fxrstor access (Paolo Bonzini)
    [1657358] {CVE-2018-10853}
    - [x86] kvm: x86: pass kvm_vcpu to kvm_read_guest_virt and kvm_write_guest_virt_system (Paolo Bonzini)
    [1657358] {CVE-2018-10853}
    - [x86] kvm: x86: introduce linear_{read,write}_system (Paolo Bonzini) [1657358] {CVE-2018-10853}
    - [char] ipmi_si: fix use-after-free of resource->name (Tony Camuso) [1714408] {CVE-2019-11811}
    - [fs] sunrpc: make visible processing error in bc_svc_process() ('J. Bruce Fields') [1653675]
    {CVE-2018-16884}
    - [fs] sunrpc: remove unused xpo_prep_reply_hdr callback ('J. Bruce Fields') [1653675] {CVE-2018-16884}
    - [fs] sunrpc: remove svc_tcp_bc_class ('J. Bruce Fields') [1653675] {CVE-2018-16884}
    - [fs] sunrpc: replace svc_serv->sv_bc_xprt by boolean flag ('J. Bruce Fields') [1653675] {CVE-2018-16884}
    - [fs] sunrpc: use-after-free in svc_process_common() ('J. Bruce Fields') [1653675] {CVE-2018-16884}
    - [fs] svcauth_gss: Close connection when dropping an incoming message ('J. Bruce Fields') [1653675]
    {CVE-2018-16884}
    - [x86] spectre: Fix an error message (Waiman Long) [1709296 1690335 1690348 1690358] {CVE-2018-12126
    CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [documentation] x86/speculation/mds: Fix documentation typo (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [documentation] Correct the possible MDS sysfs values (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [documentation] x86/mds: Add MDSUM variant to the MDS documentation (Waiman Long) [1709296 1690358
    1690348 1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation/mds: Add 'mitigations=' support for MDS (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [documentation] s390/speculation: Support 'mitigations=' cmdline option (Waiman Long) [1709296 1690358
    1690348 1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [documentation] powerpc/speculation: Support 'mitigations=' cmdline option (Waiman Long) [1709296
    1690358 1690348 1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [documentation] x86/speculation: Support 'mitigations=' cmdline option (Waiman Long) [1709296 1690358
    1690348 1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [kernel] cpu/speculation: Add 'mitigations=' cmdline option (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation/l1tf: Increase l1tf memory limit for Nehalem+ (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] spectre: Simplify spectre_v2 command line parsing (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation/mds: Properly set/clear mds_idle_clear static key (Waiman Long) [1709296 1690358
    1690348 1690335 1707292] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation/mds: Print SMT vulnerable on MSBDS with mitigations off (Waiman Long) [1709296 1690358
    1690348 1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation/mds: Fix comment (Waiman Long) [1709296 1690358 1690348 1690335] {CVE-2018-12126
    CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation/mds: Add SMT warning message (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation: Move arch_smt_update() call to after mitigation decisions (Waiman Long) [1709296
    1690358 1690348 1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation/mds: Add mds=full, nosmt cmdline option (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [kernel] x86/speculation: Remove redundant arch_smt_update() invocation (Waiman Long) [1709296 1690358
    1690348 1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] spec_ctrl: Update MDS mitigation status after late microcode load (Waiman Long) [1709296 1690358
    1690348 1690335 1710501 1710498] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] spec_ctrl: Add debugfs x86/smt_present file (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] spec_ctrl: Disable automatic enabling of STIBP with SMT on (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [documentation] documentation: Add MDS vulnerability documentation (Waiman Long) [1709296 1690358
    1690348 1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [documentation] documentation: Move L1TF to separate directory (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [documentation] x86/speculation/mds: Add mitigation mode VMWERV (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation/mds: Add sysfs reporting for MDS (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation/mds: Add mitigation control for MDS (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [documentation] x86/speculation/mds: Conditionally clear CPU buffers on idle entry (Waiman Long)
    [1709296 1690358 1690348 1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] kvm/vmx: Add MDS protection when L1D Flush is not active (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation/mds: Clear CPU buffers on exit to user (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [documentation] x86/speculation/mds: Add mds_clear_cpu_buffers() (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] kvm: Expose X86_FEATURE_MD_CLEAR to guests (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation/mds: Add BUG_MSBDS_ONLY (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation/mds: Add basic bug infrastructure for MDS (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation: Consolidate CPU whitelists (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] msr-index: Cleanup bit defines (Waiman Long) [1709296 1690358 1690348 1690335] {CVE-2018-12126
    CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] l1tf: Show actual SMT state (Waiman Long) [1709296 1690358 1690348 1690335] {CVE-2018-12126
    CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation: Simplify sysfs report of VMX L1TF vulnerability (Waiman Long) [1709296 1690358
    1690348 1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [kernel] x86/speculation: Rework SMT state change (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation: Disable STIBP when enhanced IBRS is in use (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation: Move STIPB/IBPB string conditionals out of cpu_show_common() (Waiman Long) [1709296
    1690358 1690348 1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] speculation: Enable cross-hyperthread spectre v2 STIBP mitigation (Waiman Long) [1709296 1690358
    1690348 1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] spectre_v2: Make spectre_v2_mitigation mode available (Waiman Long) [1709296 1690358 1690348
    1690335] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] spec_ctrl: Add X86_FEATURE_USE_IBPB (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] spec_ctrl: Add casting to fix compilation error (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [tools] x86/cpu: Sanitize FAM6_ATOM naming (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}
    - [x86] cpufeatures: Add Intel PCONFIG cpufeature (Waiman Long) [1709296 1690358 1690348 1690335]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130 CVE-2019-11091}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-2029.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9517");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-9363");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
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

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['3.10.0-1062.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2019-2029');
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
    {'reference':'bpftool-3.10.0-1062.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-3.10.0-1062.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-1062.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-1062.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-1062.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-1062.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-1062.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-1062.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-1062.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-1062.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-1062.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-1062.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / etc');
}
