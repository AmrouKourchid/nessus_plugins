#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-1488.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126023);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2019-3896",
    "CVE-2019-11477",
    "CVE-2019-11478",
    "CVE-2019-11479"
  );
  script_xref(name:"RHSA", value:"2019:1488");
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2019-1488)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2019-1488 advisory.

    - [net] tcp: enforce tcp_min_snd_mss in tcp_mtu_probing() (Florian Westphal) [1719614] {CVE-2019-11479}
    - [net] tcp: add tcp_min_snd_mss sysctl (Florian Westphal) [1719614] {CVE-2019-11479}
    - [net] tcp: tcp_fragment() should apply sane memory limits (Florian Westphal) [1719840] {CVE-2019-11478}
    - [net] tcp: limit payload size of sacked skbs (Florian Westphal) [1719585] {CVE-2019-11477}
    - [net] tcp: pass previous skb to tcp_shifted_skb() (Florian Westphal) [1719585] {CVE-2019-11477}
    - [lib] idr: free the top layer if idr tree has the maximum height (Denys Vlasenko) [1698139]
    {CVE-2019-3896}
    - [lib] idr: fix top layer handling (Denys Vlasenko) [1698139] {CVE-2019-3896}
    - [lib] idr: fix backtrack logic in idr_remove_all (Denys Vlasenko) [1698139] {CVE-2019-3896}
    - [x86] x86/speculation/mds: Add SMT warning message (Waiman Long) [1692386 1692387 1692388]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation/mds: Add mds=full, nosmt cmdline option (Waiman Long) [1692386 1692387 1692388]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation: Remove redundant arch_smt_update() invocation (Waiman Long) [1692386 1692387
    1692388] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/spec_ctrl: Add debugfs x86/smt_present file (Waiman Long) [1692386 1692387 1692388]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/spec_ctrl: Update MDS mitigation status after late microcode load (Waiman Long) [1692386
    1692387 1692388] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [documentation] Documentation: Add MDS vulnerability documentation (Waiman Long) [1692386 1692387
    1692388] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [documentation] Documentation: Move L1TF to separate directory (Waiman Long) [1692386 1692387 1692388]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation/mds: Add mitigation mode VMWERV (Waiman Long) [1692386 1692387 1692388]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation/mds: Add sysfs reporting for MDS (Waiman Long) [1692386 1692387 1692388]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation/mds: Add mitigation control for MDS (Waiman Long) [1692386 1692387 1692388]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation/mds: Conditionally clear CPU buffers on idle entry (Waiman Long) [1692386 1692387
    1692388] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [kvm] x86/kvm/vmx: Add MDS protection when L1D Flush is not active (Waiman Long) [1692386 1692387
    1692388] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation/mds: Clear CPU buffers on exit to user (Waiman Long) [1692386 1692387 1692388]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation/mds: Add mds_clear_cpu_buffers() (Waiman Long) [1692386 1692387 1692388]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [kvm] x86/kvm: Expose X86_FEATURE_MD_CLEAR to guests (Waiman Long) [1692386 1692387 1692388]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation/mds: Add BUG_MSBDS_ONLY (Waiman Long) [1692386 1692387 1692388] {CVE-2018-12126
    CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation/mds: Add basic bug infrastructure for MDS (Waiman Long) [1692386 1692387 1692388]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation: Consolidate CPU whitelists (Waiman Long) [1692386 1692387 1692388]
    {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/l1tf: Show actual SMT state (Waiman Long) [1692386 1692387 1692388] {CVE-2018-12126
    CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation: Simplify sysfs report of VMX L1TF vulnerability (Waiman Long) [1692386 1692387
    1692388] {CVE-2018-12126 CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/cpu: Sanitize FAM6_ATOM naming (Waiman Long) [1692386 1692387 1692388] {CVE-2018-12126
    CVE-2018-12127 CVE-2018-12130}
    - [kernel] sched/smt: Provide sched_smt_active() (Waiman Long) [1692386 1692387 1692388] {CVE-2018-12126
    CVE-2018-12127 CVE-2018-12130}
    - [x86] x86/speculation: Provide arch_smt_update() (Waiman Long) [1692386 1692387 1692388] {CVE-2018-12126
    CVE-2018-12127 CVE-2018-12130}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-1488.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3896");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/19");

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

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['2.6.32-754.15.3.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2019-1488');
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
    {'reference':'kernel-2.6.32-754.15.3.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-abi-whitelists-2.6.32-754.15.3.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-2.6.32'},
    {'reference':'kernel-debug-2.6.32-754.15.3.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-754.15.3.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-754.15.3.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-754.15.3.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-754.15.3.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-754.15.3.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-754.15.3.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.32-754.15.3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-abi-whitelists-2.6.32-754.15.3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-2.6.32'},
    {'reference':'kernel-debug-2.6.32-754.15.3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-754.15.3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-754.15.3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-754.15.3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-754.15.3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-754.15.3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-754.15.3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
