#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9008.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144903);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2020-28374", "CVE-2020-29568", "CVE-2020-29569");
  script_xref(name:"IAVB", value:"2020-B-0077-S");

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel-container (ELSA-2021-9008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ELSA-2021-9008 advisory.

    - target: fix XCOPY NAA identifier lookup (David Disseldorp)  [Orabug: 32248040]
      {CVE-2020-28374}
    - xenbus/xenbus_backend: Disallow pending watch messages (SeongJae Park)  [Orabug: 32253412]
    {CVE-2020-29568}
    - xen/xenbus: Count pending messages for each watch (SeongJae Park)  [Orabug: 32253412]  {CVE-2020-29568}
    - xen/xenbus/xen_bus_type: Support will_handle watch callback (SeongJae Park)  [Orabug: 32253412]
    {CVE-2020-29568}
    - xen/xenbus: Add 'will_handle' callback support in xenbus_watch_path() (SeongJae Park)  [Orabug:
    32253412]  {CVE-2020-29568}
    - xen/xenbus: Allow watches discard events before queueing (SeongJae Park)  [Orabug: 32253412]
    {CVE-2020-29568}
    - xen-blkback: set ring->xenblkd to NULL after kthread_stop() (Pawel Wieczorkiewicz)  [Orabug: 32260256]
    {CVE-2020-29569}
    - mm: thp: make the THP mapcount atomic against __split_huge_pmd_locked() (Andrea Arcangeli)  [Orabug:
    32212583]  {CVE-2020-29368}
    - perf/core: Fix race in the perf_mmap_close() function (Jiri Olsa)  [Orabug: 32233358]  {CVE-2020-14351}
    - icmp: randomize the global rate limiter (Eric Dumazet)  [Orabug: 32227961]  {CVE-2020-25705}
    - Fonts: Support FONT_EXTRA_WORDS macros for built-in fonts (Peilin Ye)  [Orabug: 32176263]
    {CVE-2020-28915}
    - fbdev, newport_con: Move FONT_EXTRA_WORDS macros into linux/font.h (Peilin Ye)  [Orabug: 32176263]
    {CVE-2020-28915}
    - block: Fix use-after-free in blkdev_get() (Jason Yan)  [Orabug: 32194608]  {CVE-2020-15436}
    - serial: 8250: fix null-ptr-deref in serial8250_start_tx() (Yang Yingliang)  [Orabug: 32194712]
    {CVE-2020-15437}
    - vt: Disable KD_FONT_OP_COPY (Daniel Vetter)  [Orabug: 32187748]  {CVE-2020-28974}
    - xen/events: block rogue events for some time (Juergen Gross)  [Orabug: 32177538]  {CVE-2020-27673}
    - xen/events: defer eoi in case of excessive number of events (Juergen Gross)  [Orabug: 32177538]
    {CVE-2020-27673}
    - xen/events: use a common cpu hotplug hook for event channels (Juergen Gross)  [Orabug: 32177538]
    {CVE-2020-27673}
    - xen/events: switch user event channels to lateeoi model (Juergen Gross)  [Orabug: 32177538]
    {CVE-2020-27673}
    - xen/pciback: use lateeoi irq binding (Juergen Gross)  [Orabug: 32177538]  {CVE-2020-27673}
    - xen/pvcallsback: use lateeoi irq binding (Juergen Gross)  [Orabug: 32177538]  {CVE-2020-27673}
    - xen/scsiback: use lateeoi irq binding (Juergen Gross)  [Orabug: 32177538]  {CVE-2020-27673}
    - xen/netback: use lateeoi irq binding (Juergen Gross)  [Orabug: 32177538]  {CVE-2020-27673}
    - xen/blkback: use lateeoi irq binding (Juergen Gross)  [Orabug: 32177538]  {CVE-2020-27673}
    - xen/events: add a new 'late EOI' evtchn framework (Juergen Gross)  [Orabug: 32177538]  {CVE-2020-27673}
    - xen/events: fix race in evtchn_fifo_unmask() (Juergen Gross)  [Orabug: 32177538]  {CVE-2020-27673}
    - xen/events: add a proper barrier to 2-level uevent unmasking (Juergen Gross)  [Orabug: 32177538]
    {CVE-2020-27673}
    - tty: make FONTX ioctl use the tty pointer they were actually passed (Linus Torvalds)  [Orabug: 32122729]
    {CVE-2020-25668}
    - vt: keyboard, extend func_buf_lock to readers (Jiri Slaby)  [Orabug: 32122952]  {CVE-2020-25656}
    - vt: keyboard, simplify vt_kdgkbsent (Jiri Slaby)  [Orabug: 32122952]  {CVE-2020-25656}
    - perf/core: Fix a memory leak in perf_event_parse_addr_filter() (kiyin())  [Orabug: 32131175]
    {CVE-2020-25704}
    - perf/core: Fix bad use of igrab() (Song Liu)  [Orabug: 32131175]  {CVE-2020-25704}
    - powercap: restrict energy meter to root access (Kanth Ghatraju)  [Orabug: 32138487]  {CVE-2020-8694}
    {CVE-2020-8695}
    - btrfs: inode: Verify inode mode to avoid NULL pointer dereference (Qu Wenruo)  [Orabug: 31864726]
    {CVE-2019-19816}
    - Bluetooth: A2MP: Fix not initializing all members (Luiz Augusto von Dentz)  [Orabug: 32021288]
    {CVE-2020-12352}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9008.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek-container package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29569");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  var fixed_uptrack_levels = ['4.14.35-2025.404.1.1.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2021-9008');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-container-4.14.35-2025.404.1.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-4.14.35'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek-container');
}
