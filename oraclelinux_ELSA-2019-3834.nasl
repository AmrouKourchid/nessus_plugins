#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-3834.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131110);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-11135");
  script_xref(name:"RHSA", value:"2019:3834");
  script_xref(name:"IAVA", value:"2020-A-0325-S");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2019-3834)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2019-3834 advisory.

    - [drm] drm/i915: Lower RM timeout to avoid DSI hard hangs (Dave Airlie) [1756815 1756816] {CVE-2019-0154}
    - [drm] drm/i915/gen8+: Add RC6 CTX corruption WA (Dave Airlie) [1756815 1756816] {CVE-2019-0154}
    - [drm] drm/i915/cmdparser: Ignore Length operands during command matching (Dave Airlie) [1756882 1756883]
    {CVE-2019-0155}
    - [drm] drm/i915/cmdparser: Add support for backward jumps (Dave Airlie) [1756882 1756883] {CVE-2019-0155}
    - [drm] drm/i915/cmdparser: Use explicit goto for error paths (Dave Airlie) [1756882 1756883]
    {CVE-2019-0155}
    - [drm] drm/i915: Add gen9 BCS cmdparsing (Dave Airlie) [1756882 1756883] {CVE-2019-0155}
    - [drm] drm/i915: Allow parsing of unsized batches (Dave Airlie) [1756882 1756883] {CVE-2019-0155}
    - [drm] drm/i915: Support ro ppgtt mapped cmdparser shadow buffers (Dave Airlie) [1756882 1756883]
    {CVE-2019-0155}
    - [drm] drm/i915: Add support for mandatory cmdparsing (Dave Airlie) [1756882 1756883] {CVE-2019-0155}
    - [drm] drm/i915: Remove Master tables from cmdparser (Dave Airlie) [1756882 1756883] {CVE-2019-0155}
    - [drm] drm/i915: Disable Secure Batches for gen6+ (Dave Airlie) [1756882 1756883] {CVE-2019-0155}
    - [drm] drm/i915: Rename gen7 cmdparser tables (Dave Airlie) [1756882 1756883] {CVE-2019-0155}
    - [x86] tsx: Add config options to set tsx=on|off|auto (Waiman Long) [1766539 1766540] {CVE-2019-11135}
    - [documentation] x86/speculation/taa: Add documentation for TSX Async Abort (Waiman Long) [1766539
    1766540] {CVE-2019-11135}
    - [x86] tsx: Add 'auto' option to the tsx= cmdline parameter (Waiman Long) [1766539 1766540]
    {CVE-2019-11135}
    - [x86] speculation/taa: Add sysfs reporting for TSX Async Abort (Waiman Long) [1766539 1766540]
    {CVE-2019-11135}
    - [x86] speculation/taa: Add mitigation for TSX Async Abort (Waiman Long) [1766539 1766540]
    {CVE-2019-11135}
    - [x86] cpu: Add a 'tsx=' cmdline option with TSX disabled by default (Waiman Long) [1766539 1766540]
    {CVE-2019-11135}
    - [x86] cpu: Add a helper function x86_read_arch_cap_msr() (Waiman Long) [1766539 1766540]
    {CVE-2019-11135}
    - [x86] msr: Add the IA32_TSX_CTRL MSR (Waiman Long) [1766539 1766540] {CVE-2019-11135}
    - [documentation] documentation: Add ITLB_MULTIHIT documentation (Paolo Bonzini) [1733009 1690343]
    {CVE-2018-12207}
    - [x86] kvm: x86: mmu: Recovery of shattered NX large pages (Paolo Bonzini) [1733009 1690343]
    {CVE-2018-12207}
    - [virt] kvm: Add helper function for creating VM worker threads (Paolo Bonzini) [1733009 1690343]
    {CVE-2018-12207}
    - [x86] kvm: mmu: ITLB_MULTIHIT mitigation (Paolo Bonzini) [1733009 1690343] {CVE-2018-12207}
    - [kernel] cpu/speculation: Uninline and export CPU mitigations helpers (Paolo Bonzini) [1733009 1690343]
    {CVE-2018-12207}
    - [x86] cpu: Add Tremont to the cpu vulnerability whitelist (Paolo Bonzini) [1733009 1690343]
    {CVE-2018-12207}
    - [x86] Add ITLB_MULTIHIT bug infrastructure (Paolo Bonzini) [1733009 1690343] {CVE-2018-12207}
    - [x86] kvm: vmx, svm: always run with EFER.NXE=1 when shadow paging is active (Paolo Bonzini) [1733009
    1690343] {CVE-2018-12207}
    - [x86] kvm: x86: add tracepoints around __direct_map and FNAME(fetch) (Paolo Bonzini) [1733009 1690343]
    {CVE-2018-12207}
    - [x86] kvm: x86: change kvm_mmu_page_get_gfn BUG_ON to WARN_ON (Paolo Bonzini) [1733009 1690343]
    {CVE-2018-12207}
    - [x86] kvm: x86: remove now unneeded hugepage gfn adjustment (Paolo Bonzini) [1733009 1690343]
    {CVE-2018-12207}
    - [x86] kvm: x86: make FNAME(fetch) and __direct_map more similar (Paolo Bonzini) [1733009 1690343]
    {CVE-2018-12207}
    - [x86] kvm: mmu: Do not release the page inside mmu_set_spte() (Paolo Bonzini) [1733009 1690343]
    {CVE-2018-12207}
    - [x86] kvm: x86: mmu: Remove unused parameter of __direct_map() (Paolo Bonzini) [1733009 1690343]
    {CVE-2018-12207}
    - [virt] kvm: Convert kvm_lock to a mutex (Paolo Bonzini) [1733009 1690343] {CVE-2018-12207}
    - [x86] kvm: mmu: drop vcpu param in gpte_access (Paolo Bonzini) [1733009 1690343] {CVE-2018-12207}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-3834.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11135");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/18");

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
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  var fixed_uptrack_levels = ['3.10.0-1062.4.2.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2019-3834');
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
    {'reference':'bpftool-3.10.0-1062.4.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-3.10.0-1062.4.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-1062.4.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-1062.4.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-1062.4.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-1062.4.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-1062.4.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-1062.4.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-1062.4.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-1062.4.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-1062.4.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-1062.4.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
