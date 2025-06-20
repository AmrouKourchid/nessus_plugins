##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9533.
##

include('compat.inc');

if (description)
{
  script_id(162660);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2021-4095",
    "CVE-2022-1015",
    "CVE-2022-1263",
    "CVE-2022-28388",
    "CVE-2022-28390",
    "CVE-2022-29582"
  );

  script_name(english:"Oracle Linux 8 : Unbreakable Enterprise kernel (ELSA-2022-9533)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-9533 advisory.

    - KVM: x86/speculation: Disable Fill buffer clear within guests (Pawan Gupta)  [Orabug: 34202258]
    {CVE-2022-21123} {CVE-2022-21127} {CVE-2022-21125} {CVE-2022-21166}
    - x86/speculation/mmio: Reuse SRBDS mitigation for SBDS (Pawan Gupta)  [Orabug: 34202258]
    {CVE-2022-21123} {CVE-2022-21127} {CVE-2022-21125} {CVE-2022-21166}
    - x86/speculation/srbds: Update SRBDS mitigation selection (Pawan Gupta)  [Orabug: 34202258]
    {CVE-2022-21123} {CVE-2022-21127} {CVE-2022-21125} {CVE-2022-21166}
    - x86/speculation/mmio: Add sysfs reporting for Processor MMIO Stale Data (Pawan Gupta)  [Orabug:
    34202258]  {CVE-2022-21123} {CVE-2022-21127} {CVE-2022-21125} {CVE-2022-21166}
    - x86/speculation/mmio: Enable CPU Fill buffer clearing on idle (Pawan Gupta)  [Orabug: 34202258]
    {CVE-2022-21123} {CVE-2022-21127} {CVE-2022-21125} {CVE-2022-21166}
    - x86/bugs: Group MDS, TAA & Processor MMIO Stale Data mitigations (Pawan Gupta)  [Orabug: 34202258]
    {CVE-2022-21123} {CVE-2022-21127} {CVE-2022-21125} {CVE-2022-21166}
    - x86/speculation/mmio: Add mitigation for Processor MMIO Stale Data (Pawan Gupta)  [Orabug: 34202258]
    {CVE-2022-21123} {CVE-2022-21127} {CVE-2022-21125} {CVE-2022-21166}
    - x86/speculation: Add a common function for MD_CLEAR mitigation update (Pawan Gupta)  [Orabug: 34202258]
    {CVE-2022-21123} {CVE-2022-21127} {CVE-2022-21125} {CVE-2022-21166}
    - x86/speculation/mmio: Enumerate Processor MMIO Stale Data bug (Pawan Gupta)  [Orabug: 34202258]
    {CVE-2022-21123} {CVE-2022-21127} {CVE-2022-21125} {CVE-2022-21166}
    - Documentation: Add documentation for Processor MMIO Stale Data (Pawan Gupta)  [Orabug: 34202258]
    {CVE-2022-21123} {CVE-2022-21127} {CVE-2022-21125} {CVE-2022-21166}
    - lockdown: also lock down previous kgdb use (Daniel Thompson)  [Orabug: 34152698]  {CVE-2022-21499}
    - io_uring: fix race between timeout flush and removal (Jens Axboe)  [Orabug: 34115159]  {CVE-2022-29582}
    - KVM: x86: avoid calling x86 emulator without a decoded instruction (Sean Christopherson)  [Orabug:
    34205798]  {CVE-2022-1852} {CVE-2022-1852}
    - perf: Fix sys_perf_event_open() race against self (Peter Zijlstra)  [Orabug: 34172708]  {CVE-2022-1729}
    - af_key: add __GFP_ZERO flag for compose_sadb_supported in function pfkey_register (Haimin Zhang)
    [Orabug: 34135342]  {CVE-2022-1353}
    - KVM: avoid NULL pointer dereference in kvm_dirty_ring_push (Paolo Bonzini)  [Orabug: 34048938]
    {CVE-2022-1263}
    - can: ems_usb: ems_usb_start_xmit(): fix double dev_kfree_skb() in error path (Hangyu Hua)  [Orabug:
    34048326]  {CVE-2022-28390}
    - can: usb_8dev: usb_8dev_start_xmit(): fix double dev_kfree_skb() in error path (Hangyu Hua)  [Orabug:
    34048287]  {CVE-2022-28388}
    - ALSA: pcm: Fix races among concurrent prealloc proc writes (Takashi Iwai)  [Orabug: 34007904]
    {CVE-2022-1048}
    - ALSA: pcm: Fix races among concurrent prepare and hw_params/hw_free calls (Takashi Iwai)  [Orabug:
    34007904]  {CVE-2022-1048}
    - ALSA: pcm: Fix races among concurrent read/write and buffer changes (Takashi Iwai)  [Orabug: 34007904]
    {CVE-2022-1048}
    - ALSA: pcm: Fix races among concurrent hw_params and hw_free calls (Takashi Iwai)  [Orabug: 34007904]
    {CVE-2022-1048}
    - KVM: x86/mmu: do compare-and-exchange of gPTE via the user address (Paolo Bonzini)  [Orabug: 34034593]
    {CVE-2022-1158}
    - netfilter: nf_tables: validate registers coming from userspace. (Pablo Neira Ayuso)  [Orabug: 34012906]
    {CVE-2022-1015}
    - netfilter: nf_tables: initialize registers in nft_do_chain() (Pablo Neira Ayuso)  [Orabug: 34012923]
    {CVE-2022-1016}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9533.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29582");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28390");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-modules-extra");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('aarch64' >!< cpu) audit(AUDIT_ARCH_NOT, 'aarch64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.15.0-0.30.19.el8uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2022-9533');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.15';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-5.15.0-0.30.19.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-0.30.19.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-0.30.19.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-0.30.19.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-0.30.19.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-0.30.19.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-0.30.19.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-0.30.19.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-0.30.19.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-0.30.19.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-0.30.19.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-0.30.19.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel-uek / kernel-uek-core / etc');
}
