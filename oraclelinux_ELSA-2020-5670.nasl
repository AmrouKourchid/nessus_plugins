#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5670.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136388);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2016-5244",
    "CVE-2017-7346",
    "CVE-2019-0139",
    "CVE-2019-0140",
    "CVE-2019-0144",
    "CVE-2019-9503",
    "CVE-2019-14814",
    "CVE-2019-14815",
    "CVE-2019-14816",
    "CVE-2019-19056",
    "CVE-2019-19523",
    "CVE-2019-19527",
    "CVE-2019-19532",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-9383",
    "CVE-2020-11494"
  );

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2020-5670)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2020-5670 advisory.

    - brcmfmac: add subtype check for event handling in data path (John Donnelly)  [Orabug: 30776354]
    {CVE-2019-9503}
    - mwifiex: pcie: Fix memory leak in mwifiex_pcie_alloc_cmdrsp_buf (Navid Emamdoost)  [Orabug: 31246302]
    {CVE-2019-19056}
    - drm/vmwgfx: limit the number of mip levels in vmw_gb_surface_define_ioctl() (Vladis Dronov)  [Orabug:
    31262557]  {CVE-2017-7346}
    - i40e: Increment the driver version for FW API update (Jack Vogel)  [Orabug: 31051191]  {CVE-2019-0140}
    {CVE-2019-0139} {CVE-2019-0144}
    - i40e: Update FW API version to 1.9 (Piotr Azarewicz)  [Orabug: 31051191]  {CVE-2019-0140}
    {CVE-2019-0139} {CVE-2019-0144}
    - i40e: Changed maximum supported FW API version to 1.8 (Adam Ludkiewicz)  [Orabug: 31051191]
    {CVE-2019-0140} {CVE-2019-0139} {CVE-2019-0144}
    - i40e: Stop dropping 802.1ad tags - eth proto 0x88a8 (Scott Peterson)  [Orabug: 31051191]
    {CVE-2019-0140} {CVE-2019-0139} {CVE-2019-0144}
    - i40e: fix reading LLDP configuration (Mariusz Stachura)  [Orabug: 31051191]  {CVE-2019-0140}
    {CVE-2019-0139} {CVE-2019-0144}
    - i40e: Add capability flag for stopping FW LLDP (Krzysztof Galazka)  [Orabug: 31051191]  {CVE-2019-0140}
    {CVE-2019-0139} {CVE-2019-0144}
    - i40e: refactor FW version checking (Mitch Williams)  [Orabug: 31051191]  {CVE-2019-0140} {CVE-2019-0139}
    {CVE-2019-0144}
    - i40e: shutdown all IRQs and disable MSI-X when suspended (Jacob Keller)  [Orabug: 31051191]
    {CVE-2019-0140} {CVE-2019-0139} {CVE-2019-0144}
    - i40e: prevent service task from running while we're suspended (Jacob Keller)  [Orabug: 31051191]
    {CVE-2019-0140} {CVE-2019-0139} {CVE-2019-0144}
    - i40e: don't clear suspended state until we finish resuming (Jacob Keller)  [Orabug: 31051191]
    {CVE-2019-0140} {CVE-2019-0139} {CVE-2019-0144}
    - i40e: use newer generic PM support instead of legacy PM callbacks (Jacob Keller)  [Orabug: 31051191]
    {CVE-2019-0140} {CVE-2019-0139} {CVE-2019-0144}
    - i40e: use separate state bit for miscellaneous IRQ setup (Jacob Keller)  [Orabug: 31051191]
    {CVE-2019-0140} {CVE-2019-0139} {CVE-2019-0144}
    - i40e: fix for flow director counters not wrapping as expected (Mariusz Stachura)  [Orabug: 31051191]
    {CVE-2019-0140} {CVE-2019-0139} {CVE-2019-0144}
    - i40e: relax warning message in case of version mismatch (Mariusz Stachura)  [Orabug: 31051191]
    {CVE-2019-0140} {CVE-2019-0139} {CVE-2019-0144}
    - i40e: simplify member variable accesses (Sudheer Mogilappagari)  [Orabug: 31051191]  {CVE-2019-0140}
    {CVE-2019-0139} {CVE-2019-0144}
    - i40e: Fix link down message when interface is brought up (Sudheer Mogilappagari)  [Orabug: 31051191]
    {CVE-2019-0140} {CVE-2019-0139} {CVE-2019-0144}
    - i40e: Fix unqualified module message while bringing link up (Sudheer Mogilappagari)  [Orabug: 31051191]
    {CVE-2019-0140} {CVE-2019-0139} {CVE-2019-0144}
    - HID: Fix assumption that devices have inputs (Alan Stern)  [Orabug: 31208622]  {CVE-2019-19532}
    - vgacon: Fix a UAF in vgacon_invert_region (Zhang Xiaoxu)  [Orabug: 31143947]  {CVE-2020-8649}
    {CVE-2020-8647} {CVE-2020-8647} {CVE-2020-8649} {CVE-2020-8649} {CVE-2020-8647}
    - HID: hiddev: do cleanup in failure of opening a device (Hillf Danton)  [Orabug: 31206360]
    {CVE-2019-19527}
    - HID: hiddev: avoid opening a disconnected device (Hillf Danton)  [Orabug: 31206360]  {CVE-2019-19527}
    - USB: adutux: fix use-after-free on disconnect (Johan Hovold)  [Orabug: 31233769]  {CVE-2019-19523}
    - vt: selection, push sel_lock up (Jiri Slaby)  [Orabug: 30923298]  {CVE-2020-8648}
    - vt: selection, push console lock down (Jiri Slaby)  [Orabug: 30923298]  {CVE-2020-8648}
    - vt: selection, close sel_buffer race (Jiri Slaby)  [Orabug: 30923298]  {CVE-2020-8648} {CVE-2020-8648}
    - mwifiex: Fix three heap overflow at parsing element in cfg80211_ap_settings (Wen Huang)  [Orabug:
    31104481]  {CVE-2019-14814} {CVE-2019-14815} {CVE-2019-14816} {CVE-2019-14814} {CVE-2019-14815}
    {CVE-2019-14816}
    - rds: fix an infoleak in rds_inc_info_copy (Kangjie Lu)  [Orabug: 30770962]  {CVE-2016-5244}
    - floppy: check FDC index for errors before assigning it (Linus Torvalds)  [Orabug: 31067516]
    {CVE-2020-9383}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5670.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9503");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-0140");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/07");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['4.1.12-124.39.1.el6uek', '4.1.12-124.39.1.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2020-5670');
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
    {'reference':'kernel-uek-4.1.12-124.39.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.39.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.39.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.39.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.39.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.39.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'},
    {'reference':'kernel-uek-4.1.12-124.39.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.39.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.39.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.39.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.39.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.39.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
