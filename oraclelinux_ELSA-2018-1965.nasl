#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-1965.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110749);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2017-11600", "CVE-2018-3639");
  script_xref(name:"RHSA", value:"2018:1965");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2018-1965)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2018-1965 advisory.

    - [x86] always enable eager FPU by default on non-AMD processors (Paolo Bonzini) [1589051 1589048]
    {CVE-2018-3665}
    - [x86] bugs: Switch the selection of mitigation from CPU vendor to CPU features (Waiman Long) [1584323
    1584569] {CVE-2018-3639}
    - [x86] bugs: Add AMD's SPEC_CTRL MSR usage (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] bugs: Add AMD's variant of SSB_NO (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] spec_ctrl: Fix VM guest SSBD problems (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] spec_ctrl: Eliminate TIF_SSBD checks in IBRS on/off functions (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Disable SSBD update from scheduler if not user settable (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Make ssbd_enabled writtable (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] spec_ctrl: Remove thread_info check in __wrmsr_on_cpu() (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Write per-thread SSBD state to spec_ctrl_pcp (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Add a read-only ssbd_enabled debugfs file (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] bugs/intel: Set proper CPU features and setup RDS (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] kvm: vmx: Emulate MSR_IA32_ARCH_CAPABILITIES (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] kvm: svm: Implement VIRT_SPEC_CTRL support for SSBD (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] speculation, KVM: Implement support for VIRT_SPEC_CTRL/LS_CFG (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] bugs: Rework spec_ctrl base and mask logic (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] spec_ctrl: Rework SPEC_CTRL update after late microcode loading (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Make sync_all_cpus_ibrs() write spec_ctrl_pcp value (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] bugs: Unify x86_spec_ctrl_{set_guest, restore_host} (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] speculation: Rework speculative_store_bypass_update() (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] speculation: Add virtualized speculative store bypass disable support (Waiman Long) [1584323
    1584569] {CVE-2018-3639}
    - [x86] bugs, KVM: Extend speculation control for VIRT_SPEC_CTRL (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] KVM: Rename KVM SPEC_CTRL MSR functions to match upstream (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] speculation: Handle HT correctly on AMD (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] cpufeatures: Add FEATURE_ZEN (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] cpufeatures: Disentangle SSBD enumeration (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] cpufeatures: Disentangle MSR_SPEC_CTRL enumeration from IBRS (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] speculation: Use synthetic bits for IBRS/IBPB/STIBP (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [documentation] spec_ctrl: Do some minor cleanups (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] speculation: Make 'seccomp' the default mode for Speculative Store Bypass (Waiman Long) [1584323
    1584569] {CVE-2018-3639}
    - [x86] seccomp: Move speculation migitation control to arch code (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [kernel] seccomp: Add filter flag to opt-out of SSB mitigation (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [kernel] seccomp: Use PR_SPEC_FORCE_DISABLE (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] prctl: Add force disable speculation (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [x86] spectre_v2: No mitigation if CPU not affected and no command override (Waiman Long) [1584323
    1584569] {CVE-2018-3639}
    - [x86] pti: Do not enable PTI on CPUs which are not vulnerable to Meltdown (Waiman Long) [1584323
    1584569] {CVE-2018-3639}
    - [x86] bug: Add X86_BUG_CPU_MELTDOWN and X86_BUG_SPECTRE_V[12] (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] pti: Rename CONFIG_KAISER to CONFIG_PAGE_TABLE_ISOLATION (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Sync up naming of SPEC_CTRL MSR bits with upstream (Waiman Long) [1584323 1584569]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Sync up SSBD changes with upstream (Waiman Long) [1584323 1584569] {CVE-2018-3639}
    - [powerpc] 64s: Add support for a store forwarding barrier at kernel entry/exit (Mauricio Oliveira)
    [1581045 1581036] {CVE-2018-3639}
    - [powerpc] 64s: Move the data access exception out-of-line (Mauricio Oliveira) [1581045 1581036]
    {CVE-2018-3639}
    - [net] xfrm: policy: check policy direction value (Bruno Eduardo de Oliveira Meneguele) [1479419 1479421]
    {CVE-2017-11600}
    - [x86] spec_ctrl: Fix late microcode problem with AMD (Waiman Long) [1566904 1566905] {CVE-2018-3639}
    - [x86] entry: Add missing '$' in IBRS macros (Waiman Long) [1566904 1566905] {CVE-2018-3639}
    - [x86] spec_ctrl: Clean up entry code & remove unused APIs (Waiman Long) [1566904 1566905]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Mask off SPEC_CTRL MSR bits that are managed by kernel (Waiman Long) [1566904 1566905]
    {CVE-2018-3639}
    - [x86] spec_ctrl: add support for SSBD to RHEL IBRS entry/exit macros (Waiman Long) [1566904 1566905]
    {CVE-2018-3639}
    - [fs] proc: Use CamelCase for SSBD (Waiman Long) [1566904 1566905] {CVE-2018-3639}
    - [x86] bugs: Rename _RDS to _SSBD (Waiman Long) [1566904 1566905] {CVE-2018-3639}
    - [kernel] seccomp: Enable speculation flaw mitigations (Waiman Long) [1566904 1566905] {CVE-2018-3639}
    - [fs] proc: Provide details on speculation flaw mitigations (Waiman Long) [1566904 1566905]
    {CVE-2018-3639}
    - [x86] nospec: Allow getting/setting on non-current task (Waiman Long) [1566904 1566905] {CVE-2018-3639}
    - [x86] speculation: Add prctl for Speculative Store Bypass mitigation (Waiman Long) [1566904 1566905]
    {CVE-2018-3639}
    - [x86] process: Allow runtime control of Speculative Store Bypass (Waiman Long) [1566904 1566905]
    {CVE-2018-3639}
    - [uapi] prctl: Add speculation control prctls (Waiman Long) [1566904 1566905] {CVE-2018-3639}
    - [x86] kvm/vmx: Expose SPEC_CTRL Bit(2) to the guest (Waiman Long) [1566904 1566905] {CVE-2018-3639}
    - [x86] bugs/amd: Add support to disable RDS on Fam[15, 16, 17]h if requested (Waiman Long) [1566904
    1566905] {CVE-2018-3639}
    - [x86] spec_ctrl: Sync up RDS setting with IBRS code (Waiman Long) [1566904 1566905] {CVE-2018-3639}
    - [x86] bugs: Provide boot parameters for the spec_store_bypass_disable mitigation (Waiman Long) [1566904
    1566905] {CVE-2018-3639}
    - [x86] bugs: Expose /sys/../spec_store_bypass (Waiman Long) [1566904 1566905] {CVE-2018-3639}
    - [x86] bugs: Read SPEC_CTRL MSR during boot and re-use (Waiman Long) [1566904 1566905] {CVE-2018-3639}
    - [x86] spec_ctrl: Use separate PCP variables for IBRS entry and exit (Waiman Long) [1566904 1566905]
    {CVE-2018-3639}
    - [x86] cpufeatures: Make CPU bugs sticky (Waiman Long) [1566904 1566905] {CVE-2018-3639}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-1965.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11600");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/28");

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
  var fixed_uptrack_levels = ['3.10.0-862.6.3.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-1965');
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
    {'reference':'kernel-3.10.0-862.6.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-862.6.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-862.6.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-862.6.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-862.6.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-862.6.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-862.6.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-862.6.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-862.6.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-862.6.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-862.6.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
