#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were
# extracted from OracleVM Security Advisory OVMSA-2024-0016.
##

include('compat.inc');

if (description)
{
  script_id(212214);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/10");

  script_cve_id(
    "CVE-2024-26894",
    "CVE-2024-26898",
    "CVE-2024-26973",
    "CVE-2024-27059",
    "CVE-2024-27436",
    "CVE-2024-38560",
    "CVE-2024-38599",
    "CVE-2024-39475",
    "CVE-2024-39487",
    "CVE-2024-39499",
    "CVE-2024-40904",
    "CVE-2024-40912",
    "CVE-2024-40943",
    "CVE-2024-42101",
    "CVE-2024-42148",
    "CVE-2024-45008",
    "CVE-2024-45021"
  );

  script_name(english:"OracleVM 3.4 : kernel-uek (OVMSA-2024-0016)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OracleVM host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote OracleVM system is missing necessary patches to address security updates:

    [4.1.12-124.92.3]- memcg_write_event_control(): fix a user-triggerable oops (Al Viro)  [Orabug: 37070674]
    {CVE-2024-45021}- ocfs2: fix races between hole punching and AIO+DIO (Su Yue)  [Orabug: 36835819]
    {CVE-2024-40943}[4.1.12-124.92.2]- fbdev: savage: Handle err return when savagefb_check_var failed (Cai
    Xinchen)  [Orabug: 36984058]  {CVE-2024-39475}- bnx2x: Fix multiple UBSAN array-index-out-of-bounds (Ghadi
    Elie Rahme)  [Orabug: 36897888]  {CVE-2024-42148}- vmci: prevent speculation leaks by sanitizing event in
    event_deliver() (Hagar Gamal Halim Hemdan)  [Orabug: 36835584]  {CVE-2024-39499}- aoe: fix the potential
    use-after-free problem in aoecmd_cfg_pkts (Chun-Yi Lee)  [Orabug: 36544953]
    {CVE-2024-26898}[4.1.12-124.92.1]- Input: MT - limit max slots (Tetsuo Handa)  [Orabug: 37029139]
    {CVE-2024-45008}- drm/nouveau: fix null pointer dereference in nouveau_connector_get_modes (Ma Ke)
    [Orabug: 36897642]  {CVE-2024-42101}- wifi: mac80211: Fix deadlock in ieee80211_sta_ps_deliver_wakeup()
    (Remi Pommarel)  [Orabug: 36835737]  {CVE-2024-40912}- USB: class: cdc-wdm: Fix CPU lockup caused by
    excessive log messages (Alan Stern)  [Orabug: 36835711]  {CVE-2024-40904}- bonding: Fix out-of-bounds read
    in bond_option_arp_ip_targets_set() (Sam Sun)  [Orabug: 36825250]  {CVE-2024-39487}- jffs2: prevent xattr
    node from overflowing the eraseblock (Ilya Denisyev)  [Orabug: 36753653]  {CVE-2024-38599}- scsi: bfa:
    Ensure the copied buf is NUL terminated (Bui Quang Minh)  [Orabug: 36753475]  {CVE-2024-38560}- ALSA: usb-
    audio: Stop parsing channels bits when all channels are found. (Johan Carlsson)  [Orabug: 36642150]
    {CVE-2024-27436}- USB: usb-storage: Prevent divide-by-0 error in isd200_ata_command (Alan Stern)  [Orabug:
    36598221]  {CVE-2024-27059}- fat: fix uninitialized field in nostale filehandles (Jan Kara)  [Orabug:
    36597870]  {CVE-2024-26973}- ACPI: processor_idle: Fix memory leak in acpi_processor_power_exit() (Armin
    Wolf)  [Orabug: 36544941]  {CVE-2024-26894}

Tenable has extracted the preceding description block directly from the OracleVM security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26894.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26898.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26973.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-27059.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-27436.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-38560.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-38599.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-39475.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-39487.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-39499.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-40904.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-40912.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-40943.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-42101.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-42148.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-45008.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-45021.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/OVMSA-2024-0016.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek / kernel-uek-firmware packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42148");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"OracleVM Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.1.12-124.92.3.el6uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for OVMSA-2024-0016');
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
    {'reference':'kernel-uek-4.1.12-124.92.3.el6uek', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.92.3.el6uek', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'OVS' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-firmware');
}
