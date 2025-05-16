#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-12910.
##

include('compat.inc');

if (description)
{
  script_id(183062);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2023-5090",
    "CVE-2023-20569",
    "CVE-2023-20588",
    "CVE-2023-22024",
    "CVE-2023-42753"
  );

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel-container (ELSA-2023-12910)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-12910 advisory.

    - x86: KVM: SVM: always update the x2avic msr interception (Maxim Levitsky)
      [Orabug: 35857366]  {CVE-2023-5090}
    - netfilter: ipset: add the missing IP_SET_HASH_WITH_NET0 macro for ip_set_hash_netportnet.c (Kyle Zeng)
    [Orabug: 35824287]  {CVE-2023-42753}
    - x86/microcode: Stop reprobing mitigations after late microcode load (Boris Ostrovsky)  [Orabug:
    35818857]  {CVE-2023-20569}
    - objtool/x86: Fix SRSO mess (Peter Zijlstra)  [Orabug: 35818857]  {CVE-2023-20569}
    - x86/srso: Correct the mitigation status when SMT is disabled (Borislav Petkov (AMD))  [Orabug: 35818857]
    {CVE-2023-20569}
    - objtool/x86: Fixup frame-pointer vs rethunk (Peter Zijlstra)  [Orabug: 35818857]  {CVE-2023-20569}
    - x86/srso: Disable the mitigation on unaffected configurations (Borislav Petkov (AMD))  [Orabug:
    35818857]  {CVE-2023-20569}
    - x86/retpoline: Don't clobber RFLAGS during srso_safe_ret() (Sean Christopherson)  [Orabug: 35818857]
    {CVE-2023-20569}
    - x86/srso: Explain the untraining sequences a bit more (Borislav Petkov (AMD))  [Orabug: 35818857]
    {CVE-2023-20569}
    - x86/cpu: Cleanup the untrain mess (Peter Zijlstra)  [Orabug: 35818857]  {CVE-2023-20569}
    - x86/cpu: Rename srso_(.*)_alias to srso_alias_\1 (Peter Zijlstra)  [Orabug: 35818857]  {CVE-2023-20569}
    - x86/cpu: Rename original retbleed methods (Peter Zijlstra)  [Orabug: 35818857]  {CVE-2023-20569}
    - x86/cpu: Clean up SRSO return thunk mess (Peter Zijlstra)  [Orabug: 35818857]  {CVE-2023-20569}
    - x86/alternative: Make custom return thunk unconditional (Peter Zijlstra)  [Orabug: 35818857]
    {CVE-2023-20569}
    - x86/cpu: Fix up srso_safe_ret() and __x86_return_thunk() (Peter Zijlstra)  [Orabug: 35818857]
    {CVE-2023-20569}
    - x86/cpu: Fix __x86_return_thunk symbol type (Peter Zijlstra)  [Orabug: 35818857]  {CVE-2023-20569}
    - x86/srso: Fix build breakage with the LLVM linker (Nick Desaulniers)  [Orabug: 35818857]
    {CVE-2023-20569}
    - x86/srso: Tie SBPB bit setting to microcode patch detection (Borislav Petkov (AMD))  [Orabug: 35818857]
    {CVE-2023-20569}
    - x86/srso: Fix return thunks in generated code (Josh Poimboeuf)  [Orabug: 35818857]  {CVE-2023-20569}
    - x86/srso: Add IBPB on VMEXIT (Borislav Petkov (AMD))  [Orabug: 35818857]  {CVE-2023-20569}
    - x86/srso: Add SRSO_NO support (Borislav Petkov (AMD))  [Orabug: 35818857]  {CVE-2023-20569}
    - x86/srso: Add IBPB_BRTYPE support (Borislav Petkov (AMD))  [Orabug: 35818857]  {CVE-2023-20569}
    - x86/srso: Add a Speculative RAS Overflow mitigation (Borislav Petkov (AMD))  [Orabug: 35818857]
    {CVE-2023-20569}
    - rds: Fix lack of reentrancy for connection reset with dst addr zero (Hakon Bugge)  [Orabug: 35819522]
    {CVE-2023-22024}
    - x86/CPU/AMD: Fix the DIV(0) initial fix attempt (Borislav Petkov (AMD))  [Orabug: 35776936]
    {CVE-2023-20588}
    - x86/CPU/AMD: Do not leak quotient data after a division by 0 (Borislav Petkov (AMD))  [Orabug: 35776936]
    {CVE-2023-20588}
    - xfrm: add NULL check in xfrm_update_ae_params (Lin Ma)   {CVE-2023-3772}
    - net: tap_open(): set sk_uid from current_fsuid() (Laszlo Ersek)   {CVE-2023-1076}
    - net: tun_chr_open(): set sk_uid from current_fsuid() (Laszlo Ersek)   {CVE-2023-1076}
    - net/sched: sch_qfq: account for stab overhead in qfq_enqueue (Pedro Tammela)   {CVE-2023-31436}
    - xen/netback: Fix buffer overrun triggered by unusual packet (Ross Lagerwall)   {CVE-2023-34319}
    - x86/pkeys: Revert a5eff7259790 ('x86/pkeys: Add PKRU value to init_fpstate') (Thomas Gleixner)  [Orabug:
    35714800]  {CVE-2022-40982}
    - Documentation/x86: Fix backwards on/off logic about YMM support (Dave Hansen)  [Orabug: 35714800]
    {CVE-2022-40982}
    - x86/xen: Fix secondary processors' FPU initialization (Juergen Gross)  [Orabug: 35714800]
    {CVE-2022-40982}
    - KVM: Add GDS_NO support to KVM (Daniel Sneddon)  [Orabug: 35714800]  {CVE-2022-40982}
    - x86/speculation: Add Kconfig option for GDS (Daniel Sneddon)  [Orabug: 35714800]  {CVE-2022-40982}
    - x86/speculation: Add force option to GDS mitigation (Daniel Sneddon)  [Orabug: 35714800]
    {CVE-2022-40982}
    - x86/speculation: Add Gather Data Sampling mitigation (Daniel Sneddon)  [Orabug: 35714800]
    {CVE-2022-40982}
    - x86/fpu: Move FPU initialization into arch_cpu_finalize_init() (Thomas Gleixner)  [Orabug: 35714800]
    {CVE-2022-40982}
    - x86/fpu: Mark init functions __init (Thomas Gleixner)  [Orabug: 35714800]  {CVE-2022-40982}
    - x86/fpu: Remove cpuinfo argument from init functions (Thomas Gleixner)  [Orabug: 35714800]
    {CVE-2022-40982}
    - init, x86: Move mem_encrypt_init() into arch_cpu_finalize_init() (Thomas Gleixner)  [Orabug: 35714800]
    {CVE-2022-40982}
    - init: Invoke arch_cpu_finalize_init() earlier (Thomas Gleixner)  [Orabug: 35714800]  {CVE-2022-40982}
    - init: Remove check_bugs() leftovers (Thomas Gleixner)  [Orabug: 35714800]  {CVE-2022-40982}
    - um/cpu: Switch to arch_cpu_finalize_init() (Thomas Gleixner)  [Orabug: 35714800]  {CVE-2022-40982}
    - sparc/cpu: Switch to arch_cpu_finalize_init() (Thomas Gleixner)  [Orabug: 35714800]  {CVE-2022-40982}
    - sh/cpu: Switch to arch_cpu_finalize_init() (Thomas Gleixner)  [Orabug: 35714800]  {CVE-2022-40982}
    - mips/cpu: Switch to arch_cpu_finalize_init() (Thomas Gleixner)  [Orabug: 35714800]  {CVE-2022-40982}
    - m68k/cpu: Switch to arch_cpu_finalize_init() (Thomas Gleixner)  [Orabug: 35714800]  {CVE-2022-40982}
    - ia64/cpu: Switch to arch_cpu_finalize_init() (Thomas Gleixner)  [Orabug: 35714800]  {CVE-2022-40982}
    - ARM: cpu: Switch to arch_cpu_finalize_init() (Thomas Gleixner)  [Orabug: 35714800]  {CVE-2022-40982}
    - x86/cpu: Switch to arch_cpu_finalize_init() (Thomas Gleixner)  [Orabug: 35714800]  {CVE-2022-40982}
    - init: Provide arch_cpu_finalize_init() (Thomas Gleixner)  [Orabug: 35714800]  {CVE-2022-40982}
    - media: dvb-core: Fix kernel WARNING for blocking operation in wait_event*() (Takashi Iwai)
    {CVE-2023-31084}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-12910.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek-container and / or kernel-uek-container-debug packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42753");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
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
  var fixed_uptrack_levels = ['5.4.17-2136.324.5.3.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2023-12910');
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
    {'reference':'kernel-uek-container-5.4.17-2136.324.5.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.324.5.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek-container / kernel-uek-container-debug');
}
