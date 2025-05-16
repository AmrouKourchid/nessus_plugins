#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-0007.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68177);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/30");

  script_cve_id(
    "CVE-2010-2492",
    "CVE-2010-2803",
    "CVE-2010-2955",
    "CVE-2010-2962",
    "CVE-2010-3067",
    "CVE-2010-3078",
    "CVE-2010-3079",
    "CVE-2010-3080",
    "CVE-2010-3081",
    "CVE-2010-3084",
    "CVE-2010-3298",
    "CVE-2010-3301",
    "CVE-2010-3432",
    "CVE-2010-3437",
    "CVE-2010-3442",
    "CVE-2010-3477",
    "CVE-2010-3698",
    "CVE-2010-3705",
    "CVE-2010-3861",
    "CVE-2010-3865",
    "CVE-2010-3874",
    "CVE-2010-3876",
    "CVE-2010-3880",
    "CVE-2010-3904",
    "CVE-2010-4072",
    "CVE-2010-4073",
    "CVE-2010-4074",
    "CVE-2010-4075",
    "CVE-2010-4077",
    "CVE-2010-4079",
    "CVE-2010-4080",
    "CVE-2010-4081",
    "CVE-2010-4082",
    "CVE-2010-4083",
    "CVE-2010-4158",
    "CVE-2010-4160",
    "CVE-2010-4162",
    "CVE-2010-4163",
    "CVE-2010-4242",
    "CVE-2010-4248",
    "CVE-2010-4249",
    "CVE-2010-4263",
    "CVE-2010-4525",
    "CVE-2010-4668"
  );
  script_bugtraq_id(
    42237,
    42529,
    43022,
    43062,
    43226,
    43353,
    43806,
    43809,
    43817,
    44427,
    44549,
    44630,
    44661,
    44665,
    44758,
    44762,
    44793,
    45014,
    45028,
    45037,
    45054,
    45058,
    45059,
    45062,
    45063,
    45073,
    45074,
    45208,
    45660,
    45676
  );
  script_xref(name:"RHSA", value:"2011:0007");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2011-0007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2011-0007 advisory.

    - [kvm] x86: zero kvm_vcpu_events->interrupt.pad (Marcelo Tosatti) [665471 665409] {CVE-2010-4525}

    email_6.RHSA-2011-0007 178L, 11970C written
    - [netdrv] igb: only use vlan_gro_receive if vlans are registered (Stefan Assmann) [652804 660192]
    {CVE-2010-4263}
    - [kernel] posix-cpu-timers: workaround to suppress the problems with mt exec (Oleg Nesterov) [656267
    656268] {CVE-2010-4248}
    - [fs] bio: take care not overflow page count when mapping/copying user data (Danny Feng) [652530 652531]
    {CVE-2010-4162}
    - [net] can-bcm: fix minor heap overflow (Danny Feng) [651846 651847] {CVE-2010-3874}
    - [net] filter: make sure filters dont read uninitialized memory (Jiri Pirko) [651704 651705]
    {CVE-2010-4158}
    - [net] inet_diag: Make sure we actually run the same bytecode we audited (Jiri Pirko) [651268 651269]
    {CVE-2010-3880}
    - [v4l] ivtvfb: prevent reading uninitialized stack memory (Mauro Carvalho Chehab) [648832 648833]
    {CVE-2010-4079}
    - [drm] via/ioctl.c: prevent reading uninitialized stack memory (Dave Airlie) [648718 648719]
    {CVE-2010-4082}
    - [char] nozomi: clear data before returning to userspace on TIOCGICOUNT (Mauro Carvalho Chehab) [648705
    648706] {CVE-2010-4077}
    - [serial] clean data before filling it on TIOCGICOUNT (Mauro Carvalho Chehab) [648702 648703]
    {CVE-2010-4075}
    - [net] af_unix: limit unix_tot_inflight (Neil Horman) [656761 656762] {CVE-2010-4249}
    - [block] check for proper length of iov entries in blk_rq_map_user_iov() (Danny Feng) [652958 652959]
    {CVE-2010-4163}
    - [net] Limit sendto()/recvfrom()/iovec total length to INT_MAX (Jiri Pirko) [651894 651895]
    {CVE-2010-4160}
    - [net] bluetooth: Fix missing NULL check (Jarod Wilson) [655667 655668] {CVE-2010-4242}
    - [kernel] ipc: initialize structure memory to zero for compat functions (Danny Feng) [648694 648695]
    {CVE-2010-4073}
    - [kernel] shm: fix information leak to userland (Danny Feng) [648688 648689] {CVE-2010-4072}
    - [fs] xfs: prevent reading uninitialized stack memory (Dave Chinner) [630808 630809] {CVE-2010-3078}
    - [net] fix rds_iovec page count overflow (Jiri Pirko) [647423 647424] {CVE-2010-3865}
    - [usb] serial/mos*: prevent reading uninitialized stack memory (Don Zickus) [648697 648698]
    {CVE-2010-4074}
    - [kernel] ecryptfs_uid_hash() buffer overflow (Jerome Marchand) [626320 611388] {CVE-2010-2492}
    - [sound] seq/oss - Fix double-free at error path of snd_seq_oss_open() (Jaroslav Kysela) [630554 630555]
    {CVE-2010-3080}
    - [netdrv] prevent reading uninitialized memory in hso driver (Thomas Graf) [633143 633144]
    {CVE-2010-3298}
    - [fs] aio: check for multiplication overflow in do_io_submit (Jeff Moyer) [629450 629451] {CVE-2010-3067}
    - [net] fix info leak from kernel in ethtool operation (Neil Horman) [646727 646728] {CVE-2010-3861}
    - [net] packet: fix information leak to userland (Jiri Pirko) [649899 649900] {CVE-2010-3876}
    - [net] clean up info leak in act_police (Neil Horman) [636393 636394] {CVE-2010-3477}
    - [net] Fix priv escalation in rds protocol (Neil Horman) [642899 642900] {CVE-2010-3904}
    - [v4l] Remove compat code for VIDIOCSMICROCODE (Mauro Carvalho Chehab) [642472 642473] {CVE-2010-2963}
    - [kernel] tracing: do not allow llseek to set_ftrace_filter (Jiri Olsa) [631625 631626] {CVE-2010-3079}
    - [drm] fix ioctls infoleak (Danny Feng) [626319 621437] {CVE-2010-2803}
    - [netdrv] wireless extensions: fix kernel heap content leak (John Linville) [628437 628438]
    {CVE-2010-2955}
    - [netdrv] niu: buffer overflow for ETHTOOL_GRXCLSRLALL (Danny Feng) [632071 632072] {CVE-2010-3084}
    - [virt] KVM: Fix fs/gs reload oops with invalid ldt (Avi Kivity) [639884 639885] {CVE-2010-3698}
    - [drm] i915: prevent arbitrary kernel memory write (Jerome Marchand) [637690 637691] {CVE-2010-2962}
    - [kernel] prevent heap corruption in snd_ctl_new() (Jerome Marchand) [638485 638486] {CVE-2010-3442}
    - [block] Fix pktcdvd ioctl dev_minor range check (Jerome Marchand) [638088 638089] {CVE-2010-3437}
    - [net] sctp: Fix out-of-bounds reading in sctp_asoc_get_hmac() (Jiri Pirko) [640461 640462]
    {CVE-2010-3705}
    - [net] sctp: Do not reset the packet during sctp_packet_config() (Jiri Pirko) [637681 637682]
    {CVE-2010-3432}
    - [misc] make compat_alloc_user_space() incorporate the access_ok() (Xiaotian Feng) [634465 634466]
    {CVE-2010-3081}
    - [x86] kernel: fix IA32 System Call Entry Point Vulnerability (Xiaotian Feng) [634451 634452]
    {CVE-2010-3301}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-0007.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3705");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-3904");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_page_copy_user Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['2.6.32-71.14.1.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2011-0007');
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
    {'reference':'kernel-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-debug-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-debug-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-debug / kernel-debug-devel / etc');
}
