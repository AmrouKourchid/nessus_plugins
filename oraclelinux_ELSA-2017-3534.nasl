#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-3534.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99160);
  script_version("3.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2015-4700",
    "CVE-2015-5707",
    "CVE-2015-8569",
    "CVE-2016-3140",
    "CVE-2016-3672",
    "CVE-2016-4580",
    "CVE-2016-7425",
    "CVE-2016-8399",
    "CVE-2016-8633",
    "CVE-2016-8645",
    "CVE-2016-9178",
    "CVE-2016-9588",
    "CVE-2016-10088",
    "CVE-2016-10142",
    "CVE-2017-2636",
    "CVE-2017-5970",
    "CVE-2017-6345",
    "CVE-2017-7187"
  );

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2017-3534)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2017-3534 advisory.

    - Revert 'fix minor infoleak in get_user_ex()' (Brian Maly)  [Orabug: 25790392]  {CVE-2016-9644}
    - net: ping: check minimum size on ICMP header length (Kees Cook)  [Orabug: 25766911]  {CVE-2016-8399}
    - ipv6: stop sending PTB packets for MTU < 1280 (Hagen Paul Pfeifer)  [Orabug: 25765776]  {CVE-2016-10142}
    - sg_write()/bsg_write() is not fit to be called under KERNEL_DS (Al Viro)  [Orabug: 25765445]
    {CVE-2016-10088}
    - scsi: sg: check length passed to SG_NEXT_CMD_LEN (peter chang)  [Orabug: 25751996]  {CVE-2017-7187}
    - tty: n_hdlc: get rid of racy n_hdlc.tbuf (Alexander Popov)  [Orabug: 25696686]  {CVE-2017-2636}
    - TTY: n_hdlc, fix lockdep false positive (Jiri Slaby)  [Orabug: 25696686]  {CVE-2017-2636}
    - drivers/tty/n_hdlc.c: replace kmalloc/memset by kzalloc (Fabian Frederick)  [Orabug: 25696686]
    {CVE-2017-2636}
    - x86: bpf_jit: fix compilation of large bpf programs (Alexei Starovoitov)  [Orabug: 21305080]
    {CVE-2015-4700}
    - firewire: net: guard against rx buffer overflows (Stefan Richter)  [Orabug: 25451530]  {CVE-2016-8633}
    - x86/mm/32: Enable full randomization on i386 and X86_32 (Hector Marco-Gisbert)  [Orabug: 25463927]
    {CVE-2016-3672}
    - x86 get_unmapped_area: Access mmap_legacy_base through mm_struct member (Radu Caragea)  [Orabug:
    25463927]  {CVE-2016-3672}
    - pptp: verify sockaddr_len in pptp_bind() and pptp_connect() (WANG Cong)  [Orabug: 25490335]
    {CVE-2015-8569}
    - sg_start_req(): make sure that there's not too many elements in iovec (Al Viro)  [Orabug: 25490372]
    {CVE-2015-5707}
    - kvm: nVMX: Allow L1 to intercept software exceptions (#BP and #OF) (Jim Mattson)  [Orabug: 25507195]
    {CVE-2016-9588}
    - tcp: take care of truncations done by sk_filter() (Eric Dumazet)  [Orabug: 25507230]  {CVE-2016-8645}
    - rose: limit sk_filter trim to payload (Willem de Bruijn)  [Orabug: 25507230]  {CVE-2016-8645}
    - fix minor infoleak in get_user_ex() (Al Viro)  [Orabug: 25507281]  {CVE-2016-9178}
    - scsi: arcmsr: Simplify user_len checking (Borislav Petkov)  [Orabug: 25507328]  {CVE-2016-7425}
    - scsi: arcmsr: Buffer overflow in arcmsr_iop_message_xfer() (Dan Carpenter)  [Orabug: 25507328]
    {CVE-2016-7425}
    - net: fix a kernel infoleak in x25 module (Kangjie Lu)  [Orabug: 25512413]  {CVE-2016-4580}
    - USB: digi_acceleport: do sanity checking for the number of ports (Oliver Neukum)  [Orabug: 25512471]
    {CVE-2016-3140}
    - ipv4: keep skb->dst around in presence of IP options (Eric Dumazet)  [Orabug: 25543892]  {CVE-2017-5970}
    - net/llc: avoid BUG_ON() in skb_orphan() (Eric Dumazet)  [Orabug: 25682430]  {CVE-2017-6345}
    - dccp: fix freeing skb too early for IPV6_RECVPKTINFO (Andrey Konovalov)   {CVE-2017-6074}
    - crypto: algif_hash - Only export and import on sockets with data (Herbert Xu)  [Orabug: 25417805]
    {CVE-2016-8646}
    - USB: usbfs: fix potential infoleak in devio (Kangjie Lu)  [Orabug: 25462760]  {CVE-2016-4482}
    - net: fix infoleak in llc (Kangjie Lu)  [Orabug: 25462807]  {CVE-2016-4485}
    - af_unix: Guard against other == sk in unix_dgram_sendmsg (Rainer Weikusat)  [Orabug: 25463996]
    {CVE-2013-7446}
    - unix: avoid use-after-free in ep_remove_wait_queue (Rainer Weikusat)  [Orabug: 25463996]
    {CVE-2013-7446}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-3534.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8399");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7187");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.17.4.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.17.4.el7uek");
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
  var fixed_uptrack_levels = ['3.8.13-118.17.4.el6uek', '3.8.13-118.17.4.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2017-3534');
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
    {'reference':'dtrace-modules-3.8.13-118.17.4.el6uek-0.4.5-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-118.17.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-118.17.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-118.17.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-118.17.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-118.17.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-118.17.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'},
    {'reference':'dtrace-modules-3.8.13-118.17.4.el7uek-0.4.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-118.17.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-118.17.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-118.17.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-118.17.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-118.17.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-118.17.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dtrace-modules-3.8.13-118.17.4.el6uek / dtrace-modules-3.8.13-118.17.4.el7uek / kernel-uek / etc');
}
