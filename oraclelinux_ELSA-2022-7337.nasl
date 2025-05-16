#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-7337.
##

include('compat.inc');

if (description)
{
  script_id(166937);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2022-23816",
    "CVE-2022-2588",
    "CVE-2022-23825",
    "CVE-2022-26373",
    "CVE-2022-29900",
    "CVE-2022-29901"
  );
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2022-7337)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-7337 advisory.

    - debug: lock down kgdb [Orabug: 34270798] {CVE-2022-21499}
    - x86/speculation: Add LFENCE to RSB fill sequence (Rafael Aquini) [2115073] {CVE-2022-26373}
    - x86/speculation: Protect against userspace-userspace spectreRSB (Rafael Aquini) [2090227]
    {CVE-2022-23816 CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/speculation: cope with spectre_v2=retpoline cmdline on retbleed-affected Intel CPUs (Rafael Aquini)
    [2090227] {CVE-2022-23816 CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - KVM: emulate: do not adjust size of fastop and setcc subroutines (Rafael Aquini) [2090227]
    {CVE-2022-23816 CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/kvm: fix FASTOP_SIZE when return thunks are enabled (Rafael Aquini) [2090227] {CVE-2022-23816
    CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/speculation: Disable RRSBA behavior (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86/kexec: Disable RET on kexec (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825 CVE-2022-29900
    CVE-2022-29901}
    - x86/bugs: Do not enable IBPB-on-entry when IBPB is not supported (Rafael Aquini) [2090227]
    {CVE-2022-23816 CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/bugs: Add Cannon lake to RETBleed affected CPU list (Rafael Aquini) [2090227] {CVE-2022-23816
    CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/cpu/amd: Enumerate BTC_NO (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825 CVE-2022-29900
    CVE-2022-29901}
    - x86/common: Stamp out the stepping madness (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86/cpu/amd: Add Spectral Chicken (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86/bugs: Do IBPB fallback check only once (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86/bugs: Add retbleed=ibpb (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825 CVE-2022-29900
    CVE-2022-29901}
    - x86/bugs: Report Intel retbleed vulnerability (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86/bugs: Enable STIBP for JMP2RET (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86/bugs: Add AMD retbleed= boot parameter (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86/bugs: Report AMD retbleed vulnerability (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86: Add magic AMD return-thunk (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825 CVE-2022-29900
    CVE-2022-29901}
    - x86: Use return-thunk in asm code (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86/sev: Avoid using __x86_return_thunk (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86/vsyscall_emu/64: Don't use RET in vsyscall emulation (Rafael Aquini) [2090227] {CVE-2022-23816
    CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/kvm: Fix SETcc emulation for return thunks (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86,objtool: Create .return_sites (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86: Undo return-thunk damage (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825 CVE-2022-29900
    CVE-2022-29901}
    - x86/retpoline: Use -mfunction-return (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86/cpufeatures: Move RETPOLINE flags to word 11 (Rafael Aquini) [2090227] {CVE-2022-23816
    CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - objtool: Add ELF writing capability (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86: Prepare asm files for straight-line-speculation (Rafael Aquini) [2090227] {CVE-2022-23816
    CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86: Prepare inline-asm for straight-line-speculation (Rafael Aquini) [2090227] {CVE-2022-23816
    CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/kvm: Fix fastop function ELF metadata (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - x86/kvm: Move kvm_fastop_exception to .fixup section (Rafael Aquini) [2090227] {CVE-2022-23816
    CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/vdso: Fix vDSO build if a retpoline is emitted (Rafael Aquini) [2090227] {CVE-2022-23816
    CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/cpufeatures: Combine word 11 and 12 into a new scattered features word (Rafael Aquini) [2090227]
    {CVE-2022-23816 CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/cpufeatures: Carve out CQM features retrieval (Rafael Aquini) [2090227] {CVE-2022-23816
    CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/cpufeatures: Re-tabulate the X86_FEATURE definitions (Rafael Aquini) [2090227] {CVE-2022-23816
    CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/cpufeature: Move processor tracing out of scattered features (Rafael Aquini) [2090227]
    {CVE-2022-23816 CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/cpu: Probe CPUID leaf 6 even when cpuid_level == 6 (Rafael Aquini) [2090227] {CVE-2022-23816
    CVE-2022-23825 CVE-2022-29900 CVE-2022-29901}
    - x86/alternatives: Cleanup DPRINTK macro (Rafael Aquini) [2090227] {CVE-2022-23816 CVE-2022-23825
    CVE-2022-29900 CVE-2022-29901}
    - net_sched: cls_route: remove from list when handle is 0 (Davide Caratti) [2121809] {CVE-2022-2588}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-7337.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29900");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2588");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

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
  var fixed_uptrack_levels = ['3.10.0-1160.80.1.0.1.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2022-7337');
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
    {'reference':'bpftool-3.10.0-1160.80.1.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-3.10.0-1160.80.1.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-1160.80.1.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-1160.80.1.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-1160.80.1.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-1160.80.1.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-1160.80.1.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-1160.80.1.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-1160.80.1.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-1160.80.1.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-1160.80.1.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-1160.80.1.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / etc');
}
