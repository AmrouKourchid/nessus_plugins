#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-4114.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110071);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/24");

  script_cve_id(
    "CVE-2017-18203",
    "CVE-2017-1000410",
    "CVE-2018-3639",
    "CVE-2018-5333",
    "CVE-2018-5750",
    "CVE-2018-6927",
    "CVE-2018-10323",
    "CVE-2018-10675"
  );
  script_xref(name:"IAVA", value:"2018-A-0170");
  script_xref(name:"IAVA", value:"2019-A-0025-S");

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2018-4114)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2018-4114 advisory.

    - KVM: SVM: Move spec control call after restore of GS (Thomas Gleixner)   {CVE-2018-3639}
    - x86/bugs: Fix the parameters alignment and missing void (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/bugs: Make cpu_show_common() static (Jiri Kosina)   {CVE-2018-3639}
    - x86/bugs: Fix __ssb_select_mitigation() return type (Jiri Kosina)   {CVE-2018-3639}
    - Documentation/spec_ctrl: Do some minor cleanups (Borislav Petkov)   {CVE-2018-3639}
    - proc: Use underscores for SSBD in 'status' (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/bugs: Rename _RDS to _SSBD (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/speculation: Make 'seccomp' the default mode for Speculative Store Bypass (Kees Cook)
    {CVE-2018-3639}
    - seccomp: Move speculation migitation control to arch code (Thomas Gleixner)   {CVE-2018-3639}
    - seccomp: Add filter flag to opt-out of SSB mitigation (Kees Cook)   {CVE-2018-3639}
    - seccomp: Use PR_SPEC_FORCE_DISABLE (Thomas Gleixner)   {CVE-2018-3639}
    - prctl: Add force disable speculation (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - seccomp: Enable speculation flaw mitigations (Kees Cook)   {CVE-2018-3639}
    - proc: Provide details on speculation flaw mitigations (Kees Cook)   {CVE-2018-3639}
    - nospec: Allow getting/setting on non-current task (Kees Cook)   {CVE-2018-3639}
    - x86/bugs/IBRS: Disable SSB (RDS) if IBRS is sslected for spectre_v2. (Konrad Rzeszutek Wilk)
    {CVE-2018-3639}
    - x86/speculation: Add prctl for Speculative Store Bypass mitigation (Thomas Gleixner)   {CVE-2018-3639}
    - x86: thread_info.h: move RDS from index 5 to 23 (Mihai Carabas)   {CVE-2018-3639}
    - x86/process: Allow runtime control of Speculative Store Bypass (Thomas Gleixner)   {CVE-2018-3639}
    - prctl: Add speculation control prctls (Thomas Gleixner)   {CVE-2018-3639}
    - x86/speculation: Create spec-ctrl.h to avoid include hell (Thomas Gleixner)   {CVE-2018-3639}
    - x86/KVM/VMX: Expose SPEC_CTRL Bit(2) to the guest (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/bugs/AMD: Add support to disable RDS on Fam[15,16,17]h if requested (Konrad Rzeszutek Wilk)
    {CVE-2018-3639}
    - x86/bugs: Whitelist allowed SPEC_CTRL MSR values (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/bugs/intel: Set proper CPU features and setup RDS (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/bugs: Provide boot parameters for the spec_store_bypass_disable mitigation (Konrad Rzeszutek Wilk)
    {CVE-2018-3639}
    - x86/cpufeatures: Add X86_FEATURE_RDS (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/bugs: Expose /sys/../spec_store_bypass (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/cpu/intel: Add Knights Mill to Intel family (Piotr Luc)   {CVE-2018-3639}
    - x86/cpu: Rename Merrifield2 to Moorefield (Andy Shevchenko)   {CVE-2018-3639}
    - x86/bugs, KVM: Support the combination of guest and host IBRS (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/bugs/IBRS: Warn if IBRS is enabled during boot. (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/bugs/IBRS: Use variable instead of defines for enabling IBRS (Konrad Rzeszutek Wilk)
    {CVE-2018-3639}
    - x86/bugs: Read SPEC_CTRL MSR during boot and re-use reserved bits (Konrad Rzeszutek Wilk)
    {CVE-2018-3639}
    - x86/bugs: Concentrate bug reporting into a separate function (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/bugs: Concentrate bug detection into a separate function (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/bugs/IBRS: Turn on IBRS in spectre_v2_select_mitigation (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - x86/msr: Add SPEC_CTRL_IBRS.. (Konrad Rzeszutek Wilk)   {CVE-2018-3639}
    - RDS: null pointer dereference in rds_atomic_free_op (Mohamed Ghannam)  [Orabug: 27422832]
    {CVE-2018-5333}
    - ACPI: sbshc: remove raw pointer from printk() message (Greg Kroah-Hartman)  [Orabug: 27501257]
    {CVE-2018-5750}
    - futex: Prevent overflow by strengthen input validation (Li Jinyue)  [Orabug: 27539548]  {CVE-2018-6927}
    - dm: fix race between dm_get_from_kobject() and __dm_destroy() (Hou Tao)  [Orabug: 27677556]
    {CVE-2017-18203}
    - mm/mempolicy: fix use after free when calling get_mempolicy (zhong jiang)  [Orabug: 27963519]
    {CVE-2018-10675}
    - drm: udl: Properly check framebuffer mmap offsets (Greg Kroah-Hartman)  [Orabug: 27963530]
    {CVE-2018-8781}
    - xfs: set format back to extents if xfs_bmap_extents_to_btree (Eric Sandeen)  [Orabug: 27963576]
    {CVE-2018-10323}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-4114.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10675");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-6927");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6 / 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.1.12-124.15.2.el6uek', '4.1.12-124.15.2.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-4114');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.1';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-4.1.12-124.15.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.15.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.15.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.15.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.15.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.15.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'},
    {'reference':'kernel-uek-4.1.12-124.15.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.15.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.15.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.15.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.15.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.15.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
