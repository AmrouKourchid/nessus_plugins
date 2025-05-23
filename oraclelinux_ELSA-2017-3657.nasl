#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-3657.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105144);
  script_version("3.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2017-7889", "CVE-2017-12190");

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2017-3657)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2017-3657 advisory.

    - mm: Tighten x86 /dev/mem with zeroing reads (Kees Cook)  [Orabug: 26675925]  {CVE-2017-7889}
    - more bio_map_user_iov() leak fixes (Al Viro)  [Orabug: 27069042]  {CVE-2017-12190}
    - fix unbalanced page refcounting in bio_map_user_iov (Vitaly Mayatskikh)  [Orabug: 27069042]
    {CVE-2017-12190}
    - char: lp: fix possible integer overflow in lp_setup() (Willy Tarreau)  [Orabug: 26403940]
    {CVE-2017-1000363}
    - ALSA: timer: Fix missing queue indices reset at SNDRV_TIMER_IOCTL_SELECT (Takashi Iwai)  [Orabug:
    26403956]  {CVE-2017-1000380}
    - ALSA: timer: Fix race between read and ioctl (Takashi Iwai)  [Orabug: 26403956]  {CVE-2017-1000380}
    - ALSA: timer: fix NULL pointer dereference in read()/ioctl() race (Vegard Nossum)  [Orabug: 26403956]
    {CVE-2017-1000380}
    - ALSA: timer: Fix negative queue usage by racy accesses (Takashi Iwai)  [Orabug: 26403956]
    {CVE-2017-1000380}
    - ALSA: timer: Fix race at concurrent reads (Takashi Iwai)  [Orabug: 26403956]  {CVE-2017-1000380}
    - ALSA: timer: Fix race among timer ioctls (Takashi Iwai)  [Orabug: 26403956]  {CVE-2017-1000380}
    - ipv6/dccp: do not inherit ipv6_mc_list from parent (WANG Cong)  [Orabug: 26404005]  {CVE-2017-9077}
    - ping: implement proper locking (Eric Dumazet)  [Orabug: 26540286]  {CVE-2017-2671}
    - aio: mark AIO pseudo-fs noexec (Jann Horn)  [Orabug: 26643598]  {CVE-2016-10044}
    - vfs: Commit to never having exectuables on proc and sysfs. (Eric W. Biederman)  [Orabug: 26643598]
    {CVE-2016-10044}
    - vfs, writeback: replace FS_CGROUP_WRITEBACK with SB_I_CGROUPWB (Tejun Heo)  [Orabug: 26643598]
    {CVE-2016-10044}
    - x86/acpi: Prevent out of bound access caused by broken ACPI tables (Seunghun Han)  [Orabug: 26643645]
    {CVE-2017-11473}
    - sctp: do not inherit ipv6_{mc|ac|fl}_list from parent (Eric Dumazet)  [Orabug: 26650883]
    {CVE-2017-9075}
    - [media] saa7164: fix double fetch PCIe access condition (Steven Toth)  [Orabug: 26675142]
    {CVE-2017-8831}
    - [media] saa7164: fix sparse warnings (Hans Verkuil)  [Orabug: 26675142]  {CVE-2017-8831}
    - timerfd: Protect the might cancel mechanism proper (Thomas Gleixner)  [Orabug: 26899787]
    {CVE-2017-10661}
    - scsi: scsi_transport_iscsi: fix the issue that iscsi_if_rx doesn't parse nlmsg properly (Xin Long)
    [Orabug: 26988627]  {CVE-2017-14489}
    - mqueue: fix a use-after-free in sys_mq_notify() (Cong Wang)  [Orabug: 26643556]  {CVE-2017-11176}
    - ipv6: avoid overflow of offset in ip6_find_1stfragopt (Sabrina Dubroca)  [Orabug: 27011273]
    {CVE-2017-7542}
    - packet: fix tp_reserve race in packet_set_ring (Willem de Bruijn)  [Orabug: 27002450]
    {CVE-2017-1000111}
    - Bluetooth: Properly check L2CAP config option output buffer length (Ben Seri)  [Orabug: 26796364]
    {CVE-2017-1000251}
    - xen: fix bio vec merging (Roger Pau Monne)  [Orabug: 26645550]  {CVE-2017-12134}
    - fs/exec.c: account for argv/envp pointers (Kees Cook)  [Orabug: 26638921]  {CVE-2017-1000365}
    {CVE-2017-1000365}
    - l2tp: fix racy SOCK_ZAPPED flag check in l2tp_ip{,6}_bind() (Guillaume Nault)  [Orabug: 26586047]
    {CVE-2016-10200}
    - xfs: fix two memory leaks in xfs_attr_list.c error paths (Mateusz Guzik)  [Orabug: 26586022]
    {CVE-2016-9685}
    - KEYS: Disallow keyrings beginning with '.' to be joined as session keyrings (David Howells)  [Orabug:
    26585994]  {CVE-2016-9604}
    - ipv6: fix out of bound writes in __ip6_append_data() (Eric Dumazet)  [Orabug: 26578198]  {CVE-2017-9242}
    - posix_acl: Clear SGID bit when setting file permissions (Jan Kara)  [Orabug: 25507344]  {CVE-2016-7097}
    {CVE-2016-7097}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-3657.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7889");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.20.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.20.1.el7uek");
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

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['3.8.13-118.20.1.el6uek', '3.8.13-118.20.1.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2017-3657');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '3.8';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'dtrace-modules-3.8.13-118.20.1.el6uek-0.4.5-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-118.20.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-118.20.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-118.20.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-118.20.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-118.20.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-118.20.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'},
    {'reference':'dtrace-modules-3.8.13-118.20.1.el7uek-0.4.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-118.20.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-118.20.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-118.20.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-118.20.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-118.20.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-118.20.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dtrace-modules-3.8.13-118.20.1.el6uek / dtrace-modules-3.8.13-118.20.1.el7uek / kernel-uek / etc');
}
