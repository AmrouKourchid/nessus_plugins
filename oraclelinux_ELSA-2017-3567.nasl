#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-3567.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100235);
  script_version("3.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2015-5257",
    "CVE-2015-6252",
    "CVE-2015-6937",
    "CVE-2015-9731",
    "CVE-2016-2782",
    "CVE-2017-2583",
    "CVE-2017-2647",
    "CVE-2017-5669",
    "CVE-2017-5986",
    "CVE-2017-6214",
    "CVE-2017-7184",
    "CVE-2017-7895"
  );

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2017-3567)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2017-3567 advisory.

    - nfsd: stricter decoding of write-like NFSv2/v3 ops (J. Bruce Fields)  [Orabug: 25986995]
    {CVE-2017-7895}
    - KVM: x86: fix emulation of 'MOV SS, null selector' (Paolo Bonzini)  [Orabug: 25719676]  {CVE-2017-2583}
    {CVE-2017-2583}
    - sctp: avoid BUG_ON on sctp_wait_for_sndbuf (Marcelo Ricardo Leitner)  [Orabug: 25719811]
    {CVE-2017-5986}
    - tcp: avoid infinite loop in tcp_splice_read() (Eric Dumazet)  [Orabug: 25720815]  {CVE-2017-6214}
    - USB: visor: fix null-deref at probe (Johan Hovold)  [Orabug: 25796604]  {CVE-2016-2782}
    - ipc/shm: Fix shmat mmap nil-page protection (Davidlohr Bueso)  [Orabug: 25797014]  {CVE-2017-5669}
    - vhost: actually track log eventfd file (Marc-Andre Lureau)  [Orabug: 25797056]  {CVE-2015-6252}
    - xfrm_user: validate XFRM_MSG_NEWAE incoming ESN size harder (Andy Whitcroft)  [Orabug: 25814664]
    {CVE-2017-7184}
    - xfrm_user: validate XFRM_MSG_NEWAE XFRMA_REPLAY_ESN_VAL replay_window (Andy Whitcroft)  [Orabug:
    25814664]  {CVE-2017-7184}
    - KEYS: Remove key_type::match in favour of overriding default by match_preparse (David Howells)  [Orabug:
    25823965]  {CVE-2017-2647} {CVE-2017-2647}
    - USB: whiteheat: fix potential null-deref at probe (Johan Hovold)  [Orabug: 25825107]  {CVE-2015-5257}
    - RDS: fix race condition when sending a message on unbound socket (Quentin Casasnovas)  [Orabug:
    25871048]  {CVE-2015-6937} {CVE-2015-6937}
    - udf: Check path length when reading symlink (Jan Kara)  [Orabug: 25871104]  {CVE-2015-9731}
    - udf: Treat symlink component of type 2 as / (Jan Kara)  [Orabug: 25871104]  {CVE-2015-9731}
    - udp: properly support MSG_PEEK with truncated buffers (Eric Dumazet)  [Orabug: 25874741]
    {CVE-2016-10229}
    - block: fix use-after-free in seq file (Vegard Nossum)  [Orabug: 25877531]  {CVE-2016-7910}
    - RHEL: complement upstream workaround for CVE-2016-10142. (Quentin Casasnovas)  [Orabug: 25765786]
    {CVE-2016-10142} {CVE-2016-10142}
    - net: ping: check minimum size on ICMP header length (Kees Cook)  [Orabug: 25766914]  {CVE-2016-8399}
    - ipv6: stop sending PTB packets for MTU < 1280 (Hagen Paul Pfeifer)  [Orabug: 25765786]  {CVE-2016-10142}
    - sg_write()/bsg_write() is not fit to be called under KERNEL_DS (Al Viro)  [Orabug: 25765448]
    {CVE-2016-10088}
    - scsi: sg: check length passed to SG_NEXT_CMD_LEN (peter chang)  [Orabug: 25752011]  {CVE-2017-7187}
    - tty: n_hdlc: get rid of racy n_hdlc.tbuf (Alexander Popov)  [Orabug: 25696689]  {CVE-2017-2636}
    - TTY: n_hdlc, fix lockdep false positive (Jiri Slaby)  [Orabug: 25696689]  {CVE-2017-2636}
    - drivers/tty/n_hdlc.c: replace kmalloc/memset by kzalloc (Fabian Frederick)  [Orabug: 25696689]
    {CVE-2017-2636}
    - list: introduce list_first_entry_or_null (Jiri Pirko)  [Orabug: 25696689]  {CVE-2017-2636}
    - firewire: net: guard against rx buffer overflows (Stefan Richter)  [Orabug: 25451538]  {CVE-2016-8633}
    - x86/mm/32: Enable full randomization on i386 and X86_32 (Hector Marco-Gisbert)  [Orabug: 25463929]
    {CVE-2016-3672}
    - x86 get_unmapped_area: Access mmap_legacy_base through mm_struct member (Radu Caragea)  [Orabug:
    25463929]  {CVE-2016-3672}
    - sg_start_req(): make sure that there's not too many elements in iovec (Al Viro)  [Orabug: 25490377]
    {CVE-2015-5707}
    - tcp: take care of truncations done by sk_filter() (Eric Dumazet)  [Orabug: 25507232]  {CVE-2016-8645}
    - rose: limit sk_filter trim to payload (Willem de Bruijn)  [Orabug: 25507232]  {CVE-2016-8645}
    - scsi: arcmsr: Buffer overflow in arcmsr_iop_message_xfer() (Dan Carpenter)  [Orabug: 25507330]
    {CVE-2016-7425}
    - x86: bpf_jit: fix compilation of large bpf programs (Alexei Starovoitov)  [Orabug: 25507375]
    {CVE-2015-4700}
    - net: fix a kernel infoleak in x25 module (Kangjie Lu)  [Orabug: 25512417]  {CVE-2016-4580}
    - USB: digi_acceleport: do sanity checking for the number of ports (Oliver Neukum)  [Orabug: 25512472]
    {CVE-2016-3140}
    - net/llc: avoid BUG_ON() in skb_orphan() (Eric Dumazet)  [Orabug: 25682437]  {CVE-2017-6345}
    - dccp: fix freeing skb too early for IPV6_RECVPKTINFO (Andrey Konovalov)  [Orabug: 25598277]
    {CVE-2017-6074}
    - vfs: read file_handle only once in handle_to_path (Sasha Levin)  [Orabug: 25388709]  {CVE-2015-1420}
    - USB: usbfs: fix potential infoleak in devio (Kangjie Lu)  [Orabug: 25462763]  {CVE-2016-4482}
    - net: fix infoleak in llc (Kangjie Lu)  [Orabug: 25462811]  {CVE-2016-4485}
    - af_unix: Guard against other == sk in unix_dgram_sendmsg (Rainer Weikusat)  [Orabug: 25464000]
    {CVE-2013-7446}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-3567.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7895");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5 / 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.39-400.295.2.el5uek', '2.6.39-400.295.2.el6uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2017-3567');
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
    {'reference':'kernel-uek-2.6.39-400.295.2.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.39'},
    {'reference':'kernel-uek-debug-2.6.39-400.295.2.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.39'},
    {'reference':'kernel-uek-debug-devel-2.6.39-400.295.2.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.39'},
    {'reference':'kernel-uek-devel-2.6.39-400.295.2.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.39'},
    {'reference':'kernel-uek-doc-2.6.39-400.295.2.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.39'},
    {'reference':'kernel-uek-firmware-2.6.39-400.295.2.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.39'},
    {'reference':'kernel-uek-2.6.39-400.295.2.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.39'},
    {'reference':'kernel-uek-debug-2.6.39-400.295.2.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.39'},
    {'reference':'kernel-uek-debug-devel-2.6.39-400.295.2.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.39'},
    {'reference':'kernel-uek-devel-2.6.39-400.295.2.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.39'},
    {'reference':'kernel-uek-doc-2.6.39-400.295.2.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.39'},
    {'reference':'kernel-uek-firmware-2.6.39-400.295.2.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.39'},
    {'reference':'kernel-uek-2.6.39-400.295.2.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.39'},
    {'reference':'kernel-uek-debug-2.6.39-400.295.2.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.39'},
    {'reference':'kernel-uek-debug-devel-2.6.39-400.295.2.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.39'},
    {'reference':'kernel-uek-devel-2.6.39-400.295.2.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.39'},
    {'reference':'kernel-uek-doc-2.6.39-400.295.2.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.39'},
    {'reference':'kernel-uek-firmware-2.6.39-400.295.2.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.39'},
    {'reference':'kernel-uek-2.6.39-400.295.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.39'},
    {'reference':'kernel-uek-debug-2.6.39-400.295.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.39'},
    {'reference':'kernel-uek-debug-devel-2.6.39-400.295.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.39'},
    {'reference':'kernel-uek-devel-2.6.39-400.295.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.39'},
    {'reference':'kernel-uek-doc-2.6.39-400.295.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.39'},
    {'reference':'kernel-uek-firmware-2.6.39-400.295.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.39'}
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
