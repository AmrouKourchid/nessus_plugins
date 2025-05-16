#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-7749.
##

include('compat.inc');

if (description)
{
  script_id(187270);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2023-1192",
    "CVE-2023-5345",
    "CVE-2023-20569",
    "CVE-2023-45871"
  );

  script_name(english:"Oracle Linux 9 : kernel (ELSA-2023-7749)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-7749 advisory.

    - x86/retpoline: Document some thunk handling aspects (Borislav Petkov) {CVE-2023-20569}
    - objtool: Fix return thunk patching in retpolines (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Remove unnecessary semicolon (Yang Li) {CVE-2023-20569}
    - x86/calldepth: Rename __x86_return_skl() to call_depth_return_thunk() (Josh Poimboeuf) {CVE-2023-20569}
    - x86/nospec: Refactor UNTRAIN_RET[_*] (Josh Poimboeuf) {CVE-2023-20569}
    - x86/rethunk: Use SYM_CODE_START[_LOCAL]_NOALIGN macros (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Disentangle rethunk-dependent options (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Move retbleed IBPB check into existing 'has_microcode' code block (Josh Poimboeuf)
    {CVE-2023-20569}
    - x86/bugs: Remove default case for fully switched enums (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Remove 'pred_cmd' label (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Unexport untraining functions (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Improve i-cache locality for alias mitigation (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Fix unret validation dependencies (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Fix vulnerability reporting for missing microcode (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Print mitigation for retbleed IBPB case (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Print actual mitigation if requested mitigation isn't possible (Josh Poimboeuf) [RHEL-8594]
    {CVE-2023-20569}
    - x86/srso: Fix SBPB enablement for (possible) future fixed HW (Josh Poimboeuf) {CVE-2023-20569}
    - x86,static_call: Fix static-call vs return-thunk (Peter Zijlstra) {CVE-2023-20569}
    - x86/alternatives: Remove faulty optimization (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Fix SBPB enablement for spec_rstack_overflow=off (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Don't probe microcode in a guest (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Set CPUID feature bits independently of bug or mitigation status (Josh Poimboeuf)
    {CVE-2023-20569}
    - x86/srso: Fix srso_show_state() side effect (Josh Poimboeuf) {CVE-2023-20569}
    - x86/cpu: Fix amd_check_microcode() declaration (Arnd Bergmann) {CVE-2023-20569}
    - x86/srso: Correct the mitigation status when SMT is disabled (Borislav Petkov) {CVE-2023-20569}
    - x86/static_call: Fix __static_call_fixup() (Peter Zijlstra) {CVE-2023-20569}
    - objtool/x86: Fixup frame-pointer vs rethunk (Peter Zijlstra) {CVE-2023-20569}
    - x86/srso: Explain the untraining sequences a bit more (Borislav Petkov) {CVE-2023-20569}
    - x86/cpu/kvm: Provide UNTRAIN_RET_VM (Peter Zijlstra) {CVE-2023-20569}
    - x86/cpu: Cleanup the untrain mess (Peter Zijlstra) {CVE-2023-20569}
    - x86/cpu: Rename srso_(.*)_alias to srso_alias_\1 (Peter Zijlstra) {CVE-2023-20569}
    - x86/cpu: Rename original retbleed methods (Peter Zijlstra) {CVE-2023-20569}
    - x86/cpu: Clean up SRSO return thunk mess (Peter Zijlstra) {CVE-2023-20569}
    - x86/alternative: Make custom return thunk unconditional (Peter Zijlstra) {CVE-2023-20569}
    - objtool/x86: Fix SRSO mess (Peter Zijlstra) {CVE-2023-20569}
    - x86/cpu: Fix up srso_safe_ret() and __x86_return_thunk() (Peter Zijlstra) {CVE-2023-20569}
    - x86/cpu: Fix __x86_return_thunk symbol type (Peter Zijlstra) {CVE-2023-20569}
    - x86/retpoline,kprobes: Skip optprobe check for indirect jumps with retpolines and IBT (Petr Pavlu)
    {CVE-2023-20569}
    - x86/retpoline,kprobes: Fix position of thunk sections with CONFIG_LTO_CLANG (Petr Pavlu)
    {CVE-2023-20569}
    - x86/srso: Disable the mitigation on unaffected configurations (Borislav Petkov) {CVE-2023-20569}
    - x86/CPU/AMD: Fix the DIV(0) initial fix attempt (Borislav Petkov) {CVE-2023-20588}
    - x86/retpoline: Don't clobber RFLAGS during srso_safe_ret() (Sean Christopherson) {CVE-2023-20569}
    - x86/cpu/amd: Enable Zenbleed fix for AMD Custom APU 0405 (Cristian Ciocaltea) {CVE-2023-20593}
    - driver core: cpu: Fix the fallback cpu_show_gds() name (Borislav Petkov) {CVE-2023-20569}
    - x86: Move gds_ucode_mitigated() declaration to header (Arnd Bergmann) {CVE-2023-20569}
    - x86/speculation: Add cpu_show_gds() prototype (Arnd Bergmann) {CVE-2023-20569}
    - driver core: cpu: Make cpu_show_not_affected() static (Borislav Petkov) {CVE-2023-20569}
    - x86/srso: Fix build breakage with the LLVM linker (Nick Desaulniers) {CVE-2023-20569}
    - Documentation/srso: Document IBPB aspect and fix formatting (Borislav Petkov) {CVE-2023-20569}
    - driver core: cpu: Unify redundant silly stubs (Borislav Petkov) {CVE-2023-20569}
    - Documentation/hw-vuln: Unify filename specification in index (Borislav Petkov) {CVE-2023-20569}
    - x86/CPU/AMD: Do not leak quotient data after a division by 0 (Borislav Petkov) {CVE-2023-20588}
    - x86/srso: Tie SBPB bit setting to microcode patch detection (Borislav Petkov) {CVE-2023-20569}
    - x86/srso: Add a forgotten NOENDBR annotation (Borislav Petkov) {CVE-2023-20569}
    - x86/srso: Fix return thunks in generated code (Josh Poimboeuf) {CVE-2023-20569}
    - x86/srso: Add IBPB on VMEXIT (Borislav Petkov) {CVE-2023-20569}
    - x86/srso: Add IBPB (Borislav Petkov) {CVE-2023-20569}
    - x86/srso: Add SRSO_NO support (Borislav Petkov) {CVE-2023-20569}
    - x86/srso: Add IBPB_BRTYPE support (Borislav Petkov) {CVE-2023-20569}
    - redhat/configs/x86: Enable CONFIG_CPU_SRSO (Borislav Petkov) {CVE-2023-20569}
    - x86/srso: Add a Speculative RAS Overflow mitigation (Borislav Petkov) {CVE-2023-20569}
    - x86/retbleed: Add __x86_return_thunk alignment checks (Borislav Petkov) {CVE-2023-20569}
    - x86/retbleed: Fix return thunk alignment (Borislav Petkov) {CVE-2023-20569}
    - x86/alternative: Optimize returns patching (Borislav Petkov) {CVE-2023-20569}
    - x86,objtool: Separate unret validation from unwind hints (Josh Poimboeuf) {CVE-2023-20569}
    - objtool: Add objtool_types.h (Josh Poimboeuf) {CVE-2023-20569}
    - objtool: Union instruction::{call_dest,jump_table} (Peter Zijlstra) {CVE-2023-20569}
    - x86/kprobes: Fix optprobe optimization check with CONFIG_RETHUNK (Peter Zijlstra) {CVE-2023-20569}
    - objtool: Fix SEGFAULT (Christophe Leroy) {CVE-2023-20569}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-7749.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5345");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:3:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rtla");
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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.14.0-362.13.1.el9_3'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2023-7749');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-7.2.0-362.13.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-5.14.0-362.13.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-headers-5.14.0-362.13.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-tools-5.14.0-362.13.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-362.13.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-362.13.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'perf-5.14.0-362.13.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-362.13.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-7.2.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.14.0'},
    {'reference':'kernel-abi-stablelists-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-5.14.0'},
    {'reference':'kernel-core-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-5.14.0'},
    {'reference':'kernel-cross-headers-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-debug-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-5.14.0'},
    {'reference':'kernel-debug-core-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-5.14.0'},
    {'reference':'kernel-debug-devel-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-5.14.0'},
    {'reference':'kernel-debug-devel-matched-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-matched-5.14.0'},
    {'reference':'kernel-debug-modules-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-5.14.0'},
    {'reference':'kernel-debug-modules-core-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-core-5.14.0'},
    {'reference':'kernel-debug-modules-extra-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-5.14.0'},
    {'reference':'kernel-devel-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-5.14.0'},
    {'reference':'kernel-devel-matched-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-matched-5.14.0'},
    {'reference':'kernel-headers-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-modules-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-5.14.0'},
    {'reference':'kernel-modules-core-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-core-5.14.0'},
    {'reference':'kernel-modules-extra-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-5.14.0'},
    {'reference':'kernel-tools-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'perf-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-362.13.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
