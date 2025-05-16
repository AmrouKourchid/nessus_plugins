#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1348 and 
# Oracle Linux Security Advisory ELSA-2013-1348 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70287);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2012-4398");
  script_bugtraq_id(
    52687,
    54279,
    55151,
    55361,
    56798,
    56891,
    57740,
    57743,
    57744,
    57745,
    57838,
    57986,
    58381,
    58426,
    58908,
    58977,
    58989,
    58990,
    58991,
    58992,
    58996,
    59377,
    59383,
    59390,
    59393,
    60254,
    60280,
    60375,
    60715,
    60858,
    60874,
    60893,
    60953,
    61411
  );
  script_xref(name:"RHSA", value:"2013:1348");

  script_name(english:"Oracle Linux 5 : Oracle / linux / 5 / kernel (ELSA-2013-1348)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2013-1348 advisory.

    - [kernel] signals: stop info leak via tkill and tgkill syscalls (Oleg Nesterov) [970875] {CVE-2013-2141}
    - [net] ipv6: do udp_push_pending_frames AF_INET sock pending data (Jiri Benc) [987648] {CVE-2013-4162}
    - [net] af_key: fix info leaks in notify messages (Jiri Benc) [981000] {CVE-2013-2234}
    - [net] af_key: initialize satype in key_notify_policy_flush() (Jiri Benc) [981224] {CVE-2013-2237}
    - [net] ipv6: ip6_sk_dst_check() must not assume ipv6 dst (Jiri Pirko) [981557] {CVE-2013-2232}
    - [net] sctp: Disallow new connection on a closing socket (Daniel Borkmann) [974936] {CVE-2013-2206}
    - [net] sctp: Use correct sideffect command in dup cookie handling (Daniel Borkmann) [974936]
    {CVE-2013-2206}
    - [net] sctp: deal with multiple COOKIE_ECHO chunks (Daniel Borkmann) [974936] {CVE-2013-2206}
    - [net] fix invalid free in ip_cmsg_send() callers (Petr Matousek) [980142] {CVE-2013-2224}
    - [block] cpqarray: info leak in ida_locked_ioctl() (Tomas Henzl) [971246] {CVE-2013-2147}
    - [block] cdrom: use kzalloc() for failing hardware (Frantisek Hrbata) [973104] {CVE-2013-2164}
    - [mm] use-after-free in madvise_remove() (Jacob Tanenbaum) [849736] {CVE-2012-3511}
    - [net] Bluetooth: fix possible info leak in bt_sock_recvmsg() (Radomir Vrbovsky) [955601] {CVE-2013-3224}
    - [net] Bluetooth: HCI & L2CAP information leaks (Jacob Tanenbaum) [922416] {CVE-2012-6544}
    - [misc] signal: use __ARCH_HAS_SA_RESTORER instead of SA_RESTORER (Nikola Pajkovsky) [920504]
    {CVE-2013-0914}
    - [misc] signal: always clear sa_restorer on execve (Nikola Pajkovsky) [920504] {CVE-2013-0914}
    - [misc] signal: Def __ARCH_HAS_SA_RESTORER for sa_restorer clear (Nikola Pajkovsky) [920504]
    {CVE-2013-0914}
    - [net] tg3: buffer overflow in VPD firmware parsing (Jacob Tanenbaum) [949940] {CVE-2013-1929}
    - [net] atm: update msg_namelen in vcc_recvmsg() (Nikola Pajkovsky) [955223] {CVE-2013-3222}
    - [net] llc: Fix missing msg_namelen update in llc_ui_recvmsg() (Jesper Brouer) [956097] {CVE-2013-3231}
    - [net] tipc: fix info leaks via msg_name in recv_msg/recv_stream (Jesper Brouer) [956149] {CVE-2013-3235}
    - [net] Bluetooth: RFCOMM Fix info leak in ioctl(RFCOMMGETDEVLIST) (Radomir Vrbovsky) [922407]
    {CVE-2012-6545}
    - [net] Bluetooth: RFCOMM - Fix info leak via getsockname() (Radomir Vrbovsky) [922407] {CVE-2012-6545}
    - [xen] AMD IOMMU: spot missing IO-APIC entries in IVRS table (Igor Mammedov) [910913] {CVE-2013-0153}
    - [xen] AMD, IOMMU: Make per-device interrupt remap table default (Igor Mammedov) [910913] {CVE-2013-0153}
    - [xen] AMD, IOMMU: Disable IOMMU if SATA Combined mode is on (Igor Mammedov) [910913] {CVE-2013-0153}
    - [xen] AMD, IOMMU: On creating entry clean up in remapping tables (Igor Mammedov) [910913]
    {CVE-2013-0153}
    - [xen] ACPI: acpi_table_parse() should return handler's err code (Igor Mammedov) [910913] {CVE-2013-0153}
    - [xen] introduce xzalloc() & Co (Igor Mammedov) [910913] {CVE-2013-0153}
    - [virt] xen-netback: backports (Andrew Jones) [910885] {CVE-2013-0216 CVE-2013-0217}
    - [virt] xen-netback: netif_schedulable should take a netif (Andrew Jones) [910885] {CVE-2013-0216
    CVE-2013-0217}
    - [virt] pciback: rate limit error mess from pciback_enable_msi() (Igor Mammedov) [910877] {CVE-2013-0231}
    - [net] xfrm_user: fix info leak in copy_to_user_state() (Thomas Graf) [922427] {CVE-2012-6537}
    - [net] xfrm_user: fix info leak in copy_to_user_policy() (Thomas Graf) [922427] {CVE-2012-6537}
    - [net] xfrm_user: fix info leak in copy_to_user_tmpl() (Thomas Graf) [922427] {CVE-2012-6537}
    - [net] atm: fix info leak in getsockopt(SO_ATMPVC) (Thomas Graf) [922385] {CVE-2012-6546}
    - [net] atm: fix info leak via getsockname() (Thomas Graf) [922385] {CVE-2012-6546}
    - [net] tun: fix ioctl() based info leaks (Thomas Graf) [922349] {CVE-2012-6547}
    - [net] llc, zero sockaddr_llc struct (Thomas Graf) [922329] {CVE-2012-6542}
    - [net] llc: fix info leak via getsockname() (Thomas Graf) [922329] {CVE-2012-6542}
    - [net] xfrm_user: return error pointer instead of NULL (Thomas Graf) [919387] {CVE-2013-1826}
    - [kernel] wait_for_helper: SIGCHLD from u/s cause use-after-free (Frantisek Hrbata) [858753]
    {CVE-2012-4398}
    - [kernel] Fix ____call_usermodehelper errs being silently ignored (Frantisek Hrbata) [858753]
    {CVE-2012-4398}
    - [kernel] wait_for_helper: remove unneeded do_sigaction() (Frantisek Hrbata) [858753] {CVE-2012-4398}
    - [kernel] kmod: avoid deadlock from recursive kmod call (Frantisek Hrbata) [858753] {CVE-2012-4398}
    - [kernel] kmod: make request_module() killable (Frantisek Hrbata) [858753] {CVE-2012-4398}
    - [utrace] ensure arch_ptrace() can never race with SIGKILL (Oleg Nesterov) [912072] {CVE-2013-0871}
    - [x86] msr: Add capabilities check (Nikola Pajkovsky) [908697] {CVE-2013-0268}
    - [fs] udf: Fortify loading of sparing table (Nikola Pajkovsky) [843141] {CVE-2012-3400}
    - [fs] udf: Improve table length check to avoid possible overflow (Nikola Pajkovsky) [843141]
    {CVE-2012-3400}
    - [fs] udf: Avoid run away loop when partition table is corrupted (Nikola Pajkovsky) [843141]
    {CVE-2012-3400}
    - [x86] mm: randomize SHLIB_BASE (Petr Matousek) [804954] {CVE-2012-1568}
    - [net] ipv6: discard overlapping fragment (Jiri Pirko) [874838] {CVE-2012-4444}
    - [xen] memop: limit guest specified extent order (Laszlo Ersek) [878450] {CVE-2012-5515}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-1348.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4398");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-371.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-371.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-371.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-371.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-371.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-371.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-371.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-371.el5xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.18-371.el5'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2013-1348');
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
    {'reference':'kernel-PAE-2.6.18-371.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-2.6.18'},
    {'reference':'kernel-PAE-devel-2.6.18-371.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-371.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-371.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-371.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-371.el5-1.4.10-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-371.el5PAE-1.4.10-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-371.el5debug-1.4.10-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-371.el5xen-1.4.10-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-371.el5-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-371.el5PAE-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-371.el5debug-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-371.el5xen-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.18-371.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.18'},
    {'reference':'kernel-PAE-2.6.18-371.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-2.6.18'},
    {'reference':'kernel-PAE-devel-2.6.18-371.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-devel-2.6.18'},
    {'reference':'kernel-debug-2.6.18-371.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.18'},
    {'reference':'kernel-debug-devel-2.6.18-371.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.18'},
    {'reference':'kernel-devel-2.6.18-371.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-371.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-371.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-371.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-371.el5-1.4.10-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-371.el5PAE-1.4.10-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-371.el5debug-1.4.10-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-371.el5xen-1.4.10-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-371.el5-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-371.el5PAE-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-371.el5debug-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-371.el5xen-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.18-371.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.18'},
    {'reference':'kernel-debug-2.6.18-371.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.18'},
    {'reference':'kernel-debug-devel-2.6.18-371.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.18'},
    {'reference':'kernel-devel-2.6.18-371.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-371.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-371.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-371.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-371.el5-1.4.10-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-371.el5debug-1.4.10-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-371.el5xen-1.4.10-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-371.el5-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-371.el5debug-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-371.el5xen-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-PAE / kernel-PAE-devel / etc');
}
