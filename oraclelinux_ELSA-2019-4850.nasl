#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4850.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131174);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/24");

  script_cve_id(
    "CVE-2017-15102",
    "CVE-2017-15128",
    "CVE-2017-18551",
    "CVE-2018-12207",
    "CVE-2019-11135",
    "CVE-2019-11478",
    "CVE-2019-14284",
    "CVE-2019-14835",
    "CVE-2019-15213",
    "CVE-2019-15215",
    "CVE-2019-15217",
    "CVE-2019-15916",
    "CVE-2019-16994",
    "CVE-2019-16995",
    "CVE-2019-17053",
    "CVE-2019-17055"
  );
  script_xref(name:"IAVA", value:"2020-A-0325-S");
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2019-4850)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2019-4850 advisory.

    - vhost: make sure log_num < in_num (yongduan)  [Orabug: 30312787]  {CVE-2019-14835}
    - vhost: block speculation of translated descriptors (Michael S. Tsirkin)  [Orabug: 30312787]
    {CVE-2019-14835}
    - net: hsr: fix memory leak in hsr_dev_finalize() (Mao Wenan)  [Orabug: 30444853]  {CVE-2019-16995}
    - ieee802154: enforce CAP_NET_RAW for raw sockets (Ori Nimron)  [Orabug: 30444946]  {CVE-2019-17053}
    - mISDN: enforce CAP_NET_RAW for raw sockets (Ori Nimron)  [Orabug: 30445158]  {CVE-2019-17055}
    - net: sit: fix memory leak in sit_init_net() (Mao Wenan)  [Orabug: 30445305]  {CVE-2019-16994}
    - media: dvb: usb: fix use after free in dvb_usb_device_exit (Oliver Neukum)  [Orabug: 30490491]
    {CVE-2019-15213}
    - media: cpia2_usb: first wake up, then free in disconnect (Oliver Neukum)  [Orabug: 30511741]
    {CVE-2019-15215}
    - media: usb:zr364xx:Fix KASAN:null-ptr-deref Read in zr364xx_vidioc_querycap (Vandana BN)  [Orabug:
    30532774]  {CVE-2019-15217}
    - x86/tsx: Add config options to set tsx=on|off|auto (Michal Hocko)  [Orabug: 30517133]  {CVE-2019-11135}
    - x86/speculation/taa: Add documentation for TSX Async Abort (Pawan Gupta)  [Orabug: 30517133]
    {CVE-2019-11135}
    - x86/tsx: Add 'auto' option to the tsx= cmdline parameter (Pawan Gupta)  [Orabug: 30517133]
    {CVE-2019-11135}
    - kvm/x86: Export MDS_NO=0 to guests when TSX is enabled (Pawan Gupta)  [Orabug: 30517133]
    {CVE-2019-11135}
    - x86/speculation/taa: Add sysfs reporting for TSX Async Abort (Pawan Gupta)  [Orabug: 30517133]
    {CVE-2019-11135}
    - x86/speculation/taa: Add mitigation for TSX Async Abort (Kanth Ghatraju)  [Orabug: 30517133]
    {CVE-2019-11135}
    - x86/cpu: Add a 'tsx=' cmdline option with TSX disabled by default (Pawan Gupta)  [Orabug: 30517133]
    {CVE-2019-11135}
    - x86/cpu: Add a helper function x86_read_arch_cap_msr() (Pawan Gupta)  [Orabug: 30517133]
    {CVE-2019-11135}
    - x86/msr: Add the IA32_TSX_CTRL MSR (Pawan Gupta)  [Orabug: 30517133]  {CVE-2019-11135}
    - kvm: x86: mmu: Recovery of shattered NX large pages (Junaid Shahid)  [Orabug: 30517059]
    {CVE-2018-12207}
    - kvm: Add helper function for creating VM worker threads (Junaid Shahid)  [Orabug: 30517059]
    {CVE-2018-12207}
    - kvm: mmu: ITLB_MULTIHIT mitigation (Paolo Bonzini)  [Orabug: 30517059]  {CVE-2018-12207}
    - KVM: x86: remove now unneeded hugepage gfn adjustment (Paolo Bonzini)  [Orabug: 30517059]
    {CVE-2018-12207}
    - KVM: x86: make FNAME(fetch) and __direct_map more similar (Paolo Bonzini)  [Orabug: 30517059]
    {CVE-2018-12207}
    - kvm: x86: Do not release the page inside mmu_set_spte() (Junaid Shahid)  [Orabug: 30517059]
    {CVE-2018-12207}
    - x86/cpu: Add Tremont to the cpu vulnerability whitelist (Pawan Gupta)  [Orabug: 30517059]
    {CVE-2018-12207}
    - x86: Add ITLB_MULTIHIT bug infrastructure (Pawan Gupta)  [Orabug: 30517059]  {CVE-2018-12207}
    - KVM: x86: MMU: Move mapping_level_dirty_bitmap() call in mapping_level() (Takuya Yoshikawa)  [Orabug:
    30517059]  {CVE-2018-12207}
    - Revert 'KVM: x86: use the fast way to invalidate all pages' (Sean Christopherson)  [Orabug: 30517059]
    {CVE-2018-12207}
    - kvm: Convert kvm_lock to a mutex (Junaid Shahid)  [Orabug: 30517059]  {CVE-2018-12207}
    - KVM: x86: MMU: Simplify force_pt_level calculation code in FNAME(page_fault)() (Takuya Yoshikawa)
    [Orabug: 30517059]  {CVE-2018-12207}
    - KVM: x86: MMU: Make force_pt_level bool (Takuya Yoshikawa)  [Orabug: 30517059]  {CVE-2018-12207}
    - KVM: x86: MMU: Remove unused parameter parent_pte from kvm_mmu_get_page() (Takuya Yoshikawa)  [Orabug:
    30517059]  {CVE-2018-12207}
    - KVM: x86: extend usage of RET_MMIO_PF_* constants (Paolo Bonzini)  [Orabug: 30517059]  {CVE-2018-12207}
    - KVM: x86: MMU: Make mmu_set_spte() return emulate value (Takuya Yoshikawa)  [Orabug: 30517059]
    {CVE-2018-12207}
    - KVM: x86: MMU: Move parent_pte handling from kvm_mmu_get_page() to link_shadow_page() (Takuya Yoshikawa)
    [Orabug: 30517059]  {CVE-2018-12207}
    - KVM: x86: MMU: Move initialization of parent_ptes out from kvm_mmu_alloc_page() (Takuya Yoshikawa)
    [Orabug: 30517059]  {CVE-2018-12207}
    - i2c: core-smbus: prevent stack corruption on read I2C_BLOCK_DATA (Jeremy Compostella)  [Orabug:
    30210503]  {CVE-2017-18551}
    - net-sysfs: Fix mem leak in netdev_register_kobject (YueHaibing)  [Orabug: 30350263]  {CVE-2019-15916}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-4850.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14835");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/21");

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
  var fixed_uptrack_levels = ['4.1.12-124.33.4.el6uek', '4.1.12-124.33.4.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2019-4850');
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
    {'reference':'kernel-uek-4.1.12-124.33.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.33.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.33.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.33.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.33.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.33.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'},
    {'reference':'kernel-uek-4.1.12-124.33.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.33.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.33.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.33.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.33.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.33.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
