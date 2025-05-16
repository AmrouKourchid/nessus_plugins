#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-3609.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102773);
  script_version("3.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2017-1000365", "CVE-2017-12134");
  script_xref(name:"IAVB", value:"2017-B-0108-S");
  script_xref(name:"IAVA", value:"2017-A-0253-S");

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2017-3609)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2017-3609 advisory.

    - fs/exec.c: account for argv/envp pointers (Kees Cook)  [Orabug: 26638900]  {CVE-2017-1000365}
    {CVE-2017-1000365}
    - dentry name snapshots (Al Viro)  [Orabug: 26630805]  {CVE-2017-7533}
    - mnt: Add a per mount namespace limit on the number of mounts (Eric W. Biederman)  [Orabug: 26585933]
    {CVE-2016-6213} {CVE-2016-6213}
    - ipv6: fix out of bound writes in __ip6_append_data() (Eric Dumazet)  [Orabug: 26578179]  {CVE-2017-9242}
    - KEYS: Disallow keyrings beginning with '.' to be joined as session keyrings (David Howells)  [Orabug:
    26585981]  {CVE-2016-9604} {CVE-2016-9604}
    - l2tp: fix racy SOCK_ZAPPED flag check in l2tp_ip{,6}_bind() (Guillaume Nault)  [Orabug: 26586030]
    {CVE-2016-10200}
    - ovl: move super block magic number to magic.h (Stephen Hemminger)  [Orabug: 22876737]  {CVE-2016-1575}
    {CVE-2016-1576}
    - ovl: use a minimal buffer in ovl_copy_xattr (Vito Caputo)  [Orabug: 22876737]  {CVE-2016-1575}
    {CVE-2016-1576}
    - ovl: allow zero size xattr (Miklos Szeredi)  [Orabug: 22876737]  {CVE-2016-1575} {CVE-2016-1576}
    - ovl: default permissions (Miklos Szeredi)  [Orabug: 22876737]  {CVE-2016-1575} {CVE-2016-1576}
    - nfsd: encoders mustnt use unitialized values in error cases (J. Bruce Fields)  [Orabug: 26572867]
    {CVE-2017-8797}
    - nfsd: fix undefined behavior in nfsd4_layout_verify (Ari Kauppi)  [Orabug: 26572867]  {CVE-2017-8797}
    - MacSec: fix backporting error in patches for CVE-2017-7477 (Alexey Kodanev)  [Orabug: 26481629] [Orabug:
    26368162]  {CVE-2017-7477} {CVE-2017-7477}
    - ping: implement proper locking (Eric Dumazet)  [Orabug: 26540266]  {CVE-2017-2671}
    - ipv6: Fix leak in ipv6_gso_segment(). (David S. Miller)  [Orabug: 26403963]  {CVE-2017-9074}
    - ipv6: xfrm: Handle errors reported by xfrm6_find_1stfragopt() (Ben Hutchings)  [Orabug: 26403963]
    {CVE-2017-9074}
    - ipv6: Check ip6_find_1stfragopt() return value properly. (David S. Miller)  [Orabug: 26403963]
    {CVE-2017-9074}
    - ipv6: Prevent overrun when parsing v6 header options (Craig Gallek)  [Orabug: 26403963]  {CVE-2017-9074}
    - ALSA: timer: Fix missing queue indices reset at SNDRV_TIMER_IOCTL_SELECT (Takashi Iwai)  [Orabug:
    26403948]  {CVE-2017-1000380}
    - ALSA: timer: Fix race between read and ioctl (Takashi Iwai)  [Orabug: 26403948]  {CVE-2017-1000380}
    - char: lp: fix possible integer overflow in lp_setup() (Willy Tarreau)  [Orabug: 26403936]
    {CVE-2017-1000363}
    - NFSv4: Fix callback server shutdown (Trond Myklebust)  [Orabug: 26403976]  {CVE-2017-9059}
    - SUNRPC: Refactor svc_set_num_threads() (Trond Myklebust)  [Orabug: 26403976]  {CVE-2017-9059}
    - ipv6/dccp: do not inherit ipv6_mc_list from parent (WANG Cong)  [Orabug: 26403998]  {CVE-2017-9077}
    - dccp/tcp: do not inherit mc_list from parent (Eric Dumazet)  [Orabug: 26107472]  {CVE-2017-8890}
    - nfsd: check for oversized NFSv2/v3 arguments (J. Bruce Fields)  [Orabug: 26366002]  {CVE-2017-7645}
    - macsec: dynamically allocate space for sglist (Jason A. Donenfeld)  [Orabug: 26372610]  {CVE-2017-7477}
    - macsec: avoid heap overflow in skb_to_sgvec (Jason A. Donenfeld)  [Orabug: 26372610]  {CVE-2017-7477}
    - mm: fix new crash in unmapped_area_topdown() (Hugh Dickins)  [Orabug: 26326144]  {CVE-2017-1000364}
    - mm: larger stack guard gap, between vmas (Hugh Dickins)  [Orabug: 26326144]  {CVE-2017-1000364}
    - net/packet: fix overflow in check for tp_reserve (Andrey Konovalov)  [Orabug: 25813773]  {CVE-2017-7308}
    - net/packet: fix overflow in check for tp_frame_nr (Andrey Konovalov)  [Orabug: 25813773]
    {CVE-2017-7308}
    - net/packet: fix overflow in check for priv area size (Andrey Konovalov)  [Orabug: 25813773]
    {CVE-2017-7308}
    - nfsd: stricter decoding of write-like NFSv2/v3 ops (J. Bruce Fields)  [Orabug: 25974739]
    {CVE-2017-7895}
    - udp: properly support MSG_PEEK with truncated buffers (Eric Dumazet)  [Orabug: 25876402]
    {CVE-2016-10229}
    - xfrm_user: validate XFRM_MSG_NEWAE incoming ESN size harder (Andy Whitcroft)  [Orabug: 25805996]
    {CVE-2017-7184}
    - xfrm_user: validate XFRM_MSG_NEWAE XFRMA_REPLAY_ESN_VAL replay_window (Andy Whitcroft)  [Orabug:
    25805996]  {CVE-2017-7184}
    - tty: n_hdlc: get rid of racy n_hdlc.tbuf (Alexander Popov)  [Orabug: 25802678]  {CVE-2017-2636}
    - TTY: n_hdlc, fix lockdep false positive (Jiri Slaby)  [Orabug: 25802678]  {CVE-2017-2636}
    - net/llc: avoid BUG_ON() in skb_orphan() (Eric Dumazet)  [Orabug: 25802599]  {CVE-2017-6345}
    - ip: fix IP_CHECKSUM handling (Paolo Abeni)  [Orabug: 25802576]  {CVE-2017-6347}
    - udp: fix IP_CHECKSUM handling (Eric Dumazet)  [Orabug: 25802576]  {CVE-2017-6347}
    - udp: do not expect udp headers in recv cmsg IP_CMSG_CHECKSUM (Willem de Bruijn)  [Orabug: 25802576]
    {CVE-2017-6347}
    - tcp: avoid infinite loop in tcp_splice_read() (Eric Dumazet)  [Orabug: 25802549]  {CVE-2017-6214}
    - sctp: avoid BUG_ON on sctp_wait_for_sndbuf (Marcelo Ricardo Leitner)  [Orabug: 25802515]
    {CVE-2017-5986}
    - ext4: store checksum seed in superblock (Darrick J. Wong)  [Orabug: 25802481]  {CVE-2016-10208}
    - ext4: reserve code points for the project quota feature (Theodore Tso)  [Orabug: 25802481]
    {CVE-2016-10208}
    - ext4: validate s_first_meta_bg at mount time (Eryu Guan)  [Orabug: 25802481]  {CVE-2016-10208}
    - ext4: clean up feature test macros with predicate functions (Darrick J. Wong)  [Orabug: 25802481]
    {CVE-2016-10208}
    - KVM: x86: fix emulation of 'MOV SS, null selector' (Paolo Bonzini)  [Orabug: 25802278]  {CVE-2017-2583}
    {CVE-2017-2583}
    - Revert 'fix minor infoleak in get_user_ex()' (Brian Maly)  [Orabug: 25790370]  {CVE-2016-9644}
    - net: ping: check minimum size on ICMP header length (Kees Cook)  [Orabug: 25766884]  {CVE-2016-8399}
    {CVE-2016-8399}
    - scsi: sg: check length passed to SG_NEXT_CMD_LEN (peter chang)  [Orabug: 25751395]  {CVE-2017-7187}
    - ipc/shm: Fix shmat mmap nil-page protection (Davidlohr Bueso)  [Orabug: 25717094]  {CVE-2017-5669}
    - sg_write()/bsg_write() is not fit to be called under KERNEL_DS (Al Viro)  [Orabug: 25340071]
    {CVE-2016-10088}
    - block: fix use-after-free in seq file (Vegard Nossum)  [Orabug: 25134541]  {CVE-2016-7910}
    - HID: hid-cypress: validate length of report (Greg Kroah-Hartman)  [Orabug: 25795985]  {CVE-2017-7273}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-3609.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12134");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-4.1.12-103.3.8.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-4.1.12-103.3.8.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-provider-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-shared-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  var fixed_uptrack_levels = ['4.1.12-103.3.8.el6uek', '4.1.12-103.3.8.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2017-3609');
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
    {'reference':'dtrace-modules-4.1.12-103.3.8.el6uek-0.6.1-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtrace-modules-provider-headers-0.6.1-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtrace-modules-shared-headers-0.6.1-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-4.1.12-103.3.8.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-103.3.8.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-103.3.8.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-103.3.8.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-103.3.8.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-103.3.8.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'},
    {'reference':'dtrace-modules-4.1.12-103.3.8.el7uek-0.6.1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtrace-modules-provider-headers-0.6.1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtrace-modules-shared-headers-0.6.1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-4.1.12-103.3.8.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-103.3.8.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-103.3.8.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-103.3.8.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-103.3.8.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-103.3.8.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dtrace-modules-4.1.12-103.3.8.el6uek / dtrace-modules-4.1.12-103.3.8.el7uek / dtrace-modules-provider-headers / etc');
}
