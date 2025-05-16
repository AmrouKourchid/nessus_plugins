#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12380.
##

include('compat.inc');

if (description)
{
  script_id(196903);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/21");

  script_cve_id("CVE-2024-2201");

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel-container (ELSA-2024-12380)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2024-12380 advisory.

    - KVM: x86: Add BHI_NO (Daniel Sneddon)  [Orabug: 36496846]  {CVE-2024-2201}
    - x86/bhi: Mitigate KVM by default (Pawan Gupta)  [Orabug: 36496846]  {CVE-2024-2201}
    - x86/bhi: Add BHI mitigation knob (Pawan Gupta)  [Orabug: 36496846]  {CVE-2024-2201}
    - x86/bhi: Enumerate Branch History Injection (BHI) bug (Pawan Gupta)  [Orabug: 36496846]  {CVE-2024-2201}
    - x86/bhi: Define SPEC_CTRL_BHI_DIS_S (Daniel Sneddon)  [Orabug: 36496846]  {CVE-2024-2201}
    - x86/bhi: Add support for clearing branch history at syscall entry (Pawan Gupta)  [Orabug: 36496846]
    {CVE-2024-2201}
    - x86/cpufeature: Add missing leaf enumeration (Daniel Sneddon)  [Orabug: 36496846]  {CVE-2024-2201}
    - KVM: x86: Use a switch statement and macros in __feature_translate() (Jim Mattson)  [Orabug: 36496846]
    {CVE-2024-2201}
    - KVM: x86: Advertise CPUID.(EAX=7,ECX=2):EDX[5:0] to userspace (Jim Mattson)  [Orabug: 36496846]
    {CVE-2024-2201}
    - KVM: x86: Update KVM-only leaf handling to allow for 100% KVM-only leafs (Sean Christopherson)  [Orabug:
    36496846]  {CVE-2024-2201}
    - x86/bugs: Use sysfs_emit() (Borislav Petkov)  [Orabug: 36496846]  {CVE-2024-2201}
    - x86/speculation: Reorder SRSO and GDS functions (Alexandre Chartre)  [Orabug: 36496846]  {CVE-2024-2201}
    - KVM: x86: Mask off unsupported and unknown bits of IA32_ARCH_CAPABILITIES (Jim Mattson)  [Orabug:
    36496846]  {CVE-2024-2201}
    - KVM: x86: Move reverse CPUID helpers to separate header file (Ricardo Koller)  [Orabug: 36496846]
    {CVE-2024-2201}
    - KVM: x86: Fix implicit enum conversion goof in scattered reverse CPUID code (Sean Christopherson)
    [Orabug: 36496846]  {CVE-2024-2201}
    - KVM: x86: Add support for reverse CPUID lookup of scattered features (Sean Christopherson)  [Orabug:
    36496846]  {CVE-2024-2201}
    - x86/msr: Define new bits in TSX_FORCE_ABORT MSR (Pawan Gupta)  [Orabug: 36496846]  {CVE-2024-2201}
    - objtool: Add asm version of STACK_FRAME_NON_STANDARD (Josh Poimboeuf)  [Orabug: 36496846]
    {CVE-2024-2201}
    - objtool: Only include valid definitions depending on source file type (Julien Thierry)  [Orabug:
    36496846]  {CVE-2024-2201}
    - aoe: fix the potential use-after-free problem in aoecmd_cfg_pkts (Chun-Yi Lee)   {CVE-2023-6270}
    - fbdev: sis: Error out if pixclock equals zero (Fullway Wang)   {CVE-2022-3061}
    - fbdev: savage: Error out if pixclock equals zero (Fullway Wang)   {CVE-2022-3061}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12380.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek-container and / or kernel-uek-container-debug packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2201");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['5.4.17-2136.331.7.el7', '5.4.17-2136.331.7.el8'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-12380');
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
    {'reference':'kernel-uek-container-5.4.17-2136.331.7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.331.7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'},
    {'reference':'kernel-uek-container-5.4.17-2136.331.7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.331.7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'}
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
