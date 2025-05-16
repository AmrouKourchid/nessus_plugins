#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9140.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148459);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2020-25639",
    "CVE-2020-27170",
    "CVE-2020-27171",
    "CVE-2020-28588",
    "CVE-2021-3444",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365"
  );

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel (ELSA-2021-9140)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2021-9140 advisory.

    - bpf, selftests: Fix up some test_verifier cases for unprivileged (Piotr Krysiuk)  [Orabug: 32656761]
    {CVE-2020-27170} {CVE-2020-27171}
    - bpf: Add sanity check for upper ptr_limit (Piotr Krysiuk)  [Orabug: 32656761]  {CVE-2020-27170}
    {CVE-2020-27171}
    - bpf: Simplify alu_limit masking for pointer arithmetic (Piotr Krysiuk)  [Orabug: 32656761]
    {CVE-2020-27170} {CVE-2020-27171}
    - bpf: Fix off-by-one for area size in creating mask to left (Piotr Krysiuk)  [Orabug: 32656761]
    {CVE-2020-27170} {CVE-2020-27171}
    - bpf: Prohibit alu ops for pointer types not defining ptr_limit (Piotr Krysiuk)  [Orabug: 32656761]
    {CVE-2020-27170} {CVE-2020-27171}
    - selftests/bpf: Test access to bpf map pointer (Andrey Ignatov)  [Orabug: 32656761]  {CVE-2020-27170}
    {CVE-2020-27171}
    - bpf: Fix truncation handling for mod32 dst reg wrt zero (Daniel Borkmann)  [Orabug: 32673813]
    {CVE-2021-3444}
    - bpf: Fix 32 bit src register truncation on div/mod (Daniel Borkmann)  [Orabug: 32673813]
    {CVE-2021-3444}
    - scsi: iscsi: Verify lengths on passthrough PDUs (Chris Leech)  [Orabug: 32603378]  {CVE-2021-27363}
    {CVE-2021-27364} {CVE-2021-27365}
    - scsi: iscsi: Ensure sysfs attributes are limited to PAGE_SIZE (Chris Leech)  [Orabug: 32603378]
    {CVE-2021-27363} {CVE-2021-27364} {CVE-2021-27365}
    - scsi: iscsi: Report connection state in sysfs (Gabriel Krisman Bertazi)  [Orabug: 32603378]
    {CVE-2021-27363} {CVE-2021-27364} {CVE-2021-27365}
    - sysfs: Add sysfs_emit and sysfs_emit_at to format sysfs output (Joe Perches)  [Orabug: 32603378]
    {CVE-2021-27363} {CVE-2021-27364} {CVE-2021-27365}
    - scsi: iscsi: Restrict sessions and handles to admin capabilities (Lee Duncan)  [Orabug: 32603378]
    {CVE-2021-27363} {CVE-2021-27364} {CVE-2021-27365}
    - drm/nouveau: bail out of nouveau_channel_new if channel init fails (Frantisek Hrbata)  [Orabug:
    32591559]  {CVE-2020-25639}
    - xen-blkback: fix error handling in xen_blkbk_map() (Jan Beulich)  [Orabug: 32492108]  {CVE-2021-26930}
    - xen-scsiback: dont handle error by BUG() (Jan Beulich)  [Orabug: 32492100]  {CVE-2021-26931}
    - xen-netback: dont handle error by BUG() (Jan Beulich)  [Orabug: 32492100]  {CVE-2021-26931}
    - xen-blkback: dont handle error by BUG() (Jan Beulich)  [Orabug: 32492100]  {CVE-2021-26931}
    - Xen/gntdev: correct error checking in gntdev_map_grant_pages() (Jan Beulich)  [Orabug: 32492092]
    {CVE-2021-26932}
    - Xen/gntdev: correct dev_bus_addr handling in gntdev_map_grant_pages() (Jan Beulich)  [Orabug: 32492092]
    {CVE-2021-26932}
    - Xen/x86: also check kernel mapping in set_foreign_p2m_mapping() (Jan Beulich)  [Orabug: 32492092]
    {CVE-2021-26932}
    - Xen/x86: dont bail early from clear_foreign_p2m_mapping() (Jan Beulich)  [Orabug: 32492092]
    {CVE-2021-26932}
    - nbd: freeze the queue while were adding connections (Josef Bacik)  [Orabug: 32447284]  {CVE-2021-3348}
    - futex: Handle faults correctly for PI futexes (Thomas Gleixner)  [Orabug: 32447185]  {CVE-2021-3347}
    - futex: Simplify fixup_pi_state_owner() (Thomas Gleixner)  [Orabug: 32447185]  {CVE-2021-3347}
    - futex: Use pi_state_update_owner() in put_pi_state() (Thomas Gleixner)  [Orabug: 32447185]
    {CVE-2021-3347}
    - rtmutex: Remove unused argument from rt_mutex_proxy_unlock() (Thomas Gleixner)  [Orabug: 32447185]
    {CVE-2021-3347}
    - futex: Provide and use pi_state_update_owner() (Thomas Gleixner)  [Orabug: 32447185]  {CVE-2021-3347}
    - futex: Replace pointless printk in fixup_owner() (Thomas Gleixner)  [Orabug: 32447185]  {CVE-2021-3347}
    - futex: Ensure the correct return value from futex_lock_pi() (Thomas Gleixner)  [Orabug: 32447185]
    {CVE-2021-3347}
    - netfilter: add and use nf_hook_slow_list() (Florian Westphal)  [Orabug: 32372529]  {CVE-2021-20177}
    - target: fix XCOPY NAA identifier lookup (David Disseldorp)  [Orabug: 32374281]  {CVE-2020-28374}
    - mwifiex: Fix possible buffer overflows in mwifiex_cmd_802_11_ad_hoc_start (Zhang Xiaohui)  [Orabug:
    32349202]  {CVE-2020-36158}
    - xen-blkback: set ring->xenblkd to NULL after kthread_stop() (Pawel Wieczorkiewicz)  [Orabug: 32260251]
    {CVE-2020-29569}
    - xenbus/xenbus_backend: Disallow pending watch messages (SeongJae Park)  [Orabug: 32253408]
    {CVE-2020-29568}
    - xen/xenbus: Count pending messages for each watch (SeongJae Park)  [Orabug: 32253408]  {CVE-2020-29568}
    - xen/xenbus/xen_bus_type: Support will_handle watch callback (SeongJae Park)  [Orabug: 32253408]
    {CVE-2020-29568}
    - xen/xenbus: Add will_handle callback support in xenbus_watch_path() (SeongJae Park)  [Orabug: 32253408]
    {CVE-2020-29568}
    - xen/xenbus: Allow watches discard events before queueing (SeongJae Park)  [Orabug: 32253408]
    {CVE-2020-29568}
    - futex: Fix inode life-time issue (Peter Zijlstra)  [Orabug: 32233513]  {CVE-2020-14381}
    - lib/syscall: fix syscall registers retrieval on 32-bit platforms (Willy Tarreau)   {CVE-2020-28588}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9140.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3444");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.4.17-2102.200.13.el7uek', '5.4.17-2102.200.13.el8uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2021-9140');
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
    {'reference':'kernel-uek-5.4.17-2102.200.13.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2102.200.13.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2102.200.13.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2102.200.13.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2102.200.13.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2102.200.13.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-libs-5.4.17-2102.200.13.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-5.4.17'},
    {'reference':'perf-5.4.17-2102.200.13.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-5.4.17'},
    {'reference':'python-perf-5.4.17-2102.200.13.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2102.200.13.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2102.200.13.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2102.200.13.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2102.200.13.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2102.200.13.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2102.200.13.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-libs-5.4.17-2102.200.13.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-5.4.17'},
    {'reference':'perf-5.4.17-2102.200.13.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-5.4.17'},
    {'reference':'python-perf-5.4.17-2102.200.13.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2102.200.13.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2102.200.13.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2102.200.13.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2102.200.13.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2102.200.13.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2102.200.13.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2102.200.13.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2102.200.13.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2102.200.13.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2102.200.13.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
