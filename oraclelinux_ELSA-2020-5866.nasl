#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5866.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141207);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2016-10905",
    "CVE-2016-10906",
    "CVE-2017-8924",
    "CVE-2017-8925",
    "CVE-2017-16528",
    "CVE-2018-9415",
    "CVE-2018-16884",
    "CVE-2018-20856",
    "CVE-2019-3846",
    "CVE-2019-3874",
    "CVE-2019-5108",
    "CVE-2019-6974",
    "CVE-2019-7221",
    "CVE-2019-7222",
    "CVE-2019-11487",
    "CVE-2019-14898",
    "CVE-2019-15218",
    "CVE-2019-15505",
    "CVE-2019-15927",
    "CVE-2019-16746",
    "CVE-2019-17075",
    "CVE-2019-18885",
    "CVE-2019-19052",
    "CVE-2019-19073",
    "CVE-2019-19768",
    "CVE-2019-19965",
    "CVE-2019-20054",
    "CVE-2019-20096",
    "CVE-2019-20812",
    "CVE-2020-1749",
    "CVE-2020-10720",
    "CVE-2020-10751",
    "CVE-2020-10769",
    "CVE-2020-14314",
    "CVE-2020-14331",
    "CVE-2020-25212",
    "CVE-2020-25284",
    "CVE-2020-25285"
  );
  script_bugtraq_id(
    98451,
    98462,
    106253,
    106963,
    107127,
    107294,
    107488,
    108054,
    108521
  );

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2020-5866)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2020-5866 advisory.

    - kvm: fix kvm_ioctl_create_device() reference counting (CVE-2019-6974) (Jann Horn)  [Orabug: 29434845]
    {CVE-2019-6974}
    - KVM: nVMX: unconditionally cancel preemption timer in free_nested (CVE-2019-7221) (Peter Shier)
    [Orabug: 29434898]  {CVE-2019-7221}
    - KVM: x86: work around leak of uninitialized stack contents (CVE-2019-7222) (Paolo Bonzini)  [Orabug:
    29434924]  {CVE-2019-7222}
    - net: arc_emac: fix koops caused by sk_buff free (Alexander Kochetkov)  [Orabug: 30254239]
    {CVE-2016-10906}
    - GFS2: don't set rgrp gl_object until it's inserted into rgrp tree (Bob Peterson)  [Orabug: 30254251]
    {CVE-2016-10905}
    - GFS2: Fix rgrp end rounding problem for bsize < page size (Bob Peterson)  [Orabug: 30254251]
    {CVE-2016-10905}
    - net: ipv6_stub: use ip6_dst_lookup_flow instead of ip6_dst_lookup (Sabrina Dubroca)  [Orabug: 31872821]
    {CVE-2020-1749}
    - nfs: Fix getxattr kernel panic and memory overflow (Jeffrey Mitchell)  [Orabug: 31872910]
    {CVE-2020-25212}
    - rbd: require global CAP_SYS_ADMIN for mapping and unmapping (Ilya Dryomov)  [Orabug: 31884169]
    {CVE-2020-25284}
    - mm/hugetlb: fix a race between hugetlb sysctl handlers (Muchun Song)  [Orabug: 31884239]
    {CVE-2020-25285}
    - ext4: fix potential negative array index in do_split() (Eric Sandeen)  [Orabug: 31895331]
    {CVE-2020-14314}
    - ARM: amba: Fix race condition with driver_override (Geert Uytterhoeven)  [Orabug: 29671212]
    {CVE-2018-9415}
    - block: blk_init_allocated_queue() set q->fq as NULL in the fail case (xiao jin)  [Orabug: 30120513]
    {CVE-2018-20856}
    - USB: serial: omninet: fix reference leaks at open (Johan Hovold)  [Orabug: 30484761]  {CVE-2017-8925}
    - nl80211: validate beacon head (Johannes Berg)  [Orabug: 30556264]  {CVE-2019-16746}
    - cfg80211: Use const more consistently in for_each_element macros (Jouni Malinen)  [Orabug: 30556264]
    {CVE-2019-16746}
    - cfg80211: add and use strongly typed element iteration macros (Johannes Berg)  [Orabug: 30556264]
    {CVE-2019-16746}
    - cfg80211: add helper to find an IE that matches a byte-array (Luca Coelho)  [Orabug: 30556264]
    {CVE-2019-16746}
    - cfg80211: allow finding vendor with OUI without specifying the OUI type (Emmanuel Grumbach)  [Orabug:
    30556264]  {CVE-2019-16746}
    - dccp: Fix memleak in __feat_register_sp (YueHaibing)  [Orabug: 30732821]  {CVE-2019-20096}
    - fs/proc/proc_sysctl.c: Fix a NULL pointer dereference (YueHaibing)  [Orabug: 30732938]  {CVE-2019-20054}
    - fs/proc/proc_sysctl.c: fix NULL pointer dereference in put_links (YueHaibing)  [Orabug: 30732938]
    {CVE-2019-20054}
    - scsi: libsas: stop discovering if oob mode is disconnected (Jason Yan)  [Orabug: 30770913]
    {CVE-2019-19965}
    - kernel/sysctl.c: fix out-of-bounds access when setting file-max (Will Deacon)  [Orabug: 31350720]
    {CVE-2019-14898}
    - sysctl: handle overflow for file-max (Christian Brauner)  [Orabug: 31350720]  {CVE-2019-14898}
    - ath9k_htc: release allocated buffer if timed out (Navid Emamdoost)  [Orabug: 31351572]  {CVE-2019-19073}
    - can: gs_usb: gs_can_open(): prevent memory leak (Navid Emamdoost)  [Orabug: 31351682]  {CVE-2019-19052}
    - ALSA: usb-audio: Avoid access before bLength check in build_audio_procunit() (Takashi Iwai)  [Orabug:
    31351837]  {CVE-2019-15927}
    - media: usb: siano: Fix general protection fault in smsusb (Alan Stern)  [Orabug: 31351875]
    {CVE-2019-15218}
    - net-gro: fix use-after-free read in napi_gro_frags() (Eric Dumazet)  [Orabug: 31856195]
    {CVE-2020-10720}
    - ALSA: seq: Cancel pending autoload work at unbinding device (Takashi Iwai)  [Orabug: 31352045]
    {CVE-2017-16528}
    - USB: serial: io_ti: fix information leak in completion handler (Johan Hovold)  [Orabug: 31352084]
    {CVE-2017-8924}
    - blktrace: Protect q->blk_trace with RCU (Jan Kara)  [Orabug: 31123576]  {CVE-2019-19768}
    - media: technisat-usb2: break out of loop at end of buffer (Sean Young)  [Orabug: 31224554]
    {CVE-2019-15505}
    - btrfs: merge btrfs_find_device and find_device (Anand Jain)  [Orabug: 31351746]  {CVE-2019-18885}
    - RDMA/cxgb4: Do not dma memory off of the stack (Greg KH)  [Orabug: 31351783]  {CVE-2019-17075}
    - mwifiex: Abort at too short BSS descriptor element (Takashi Iwai)  [Orabug: 31351916]  {CVE-2019-3846}
    - mwifiex: Fix possible buffer overflows at parsing bss descriptor (Takashi Iwai)  [Orabug: 31351916]
    {CVE-2019-3846} {CVE-2019-3846}
    - repair kABI breakage from 'fs: prevent page refcount overflow in pipe_buf_get' (Dan Duval)  [Orabug:
    31351941]  {CVE-2019-11487}
    - mm: prevent get_user_pages() from overflowing page refcount (Linus Torvalds)  [Orabug: 31351941]
    {CVE-2019-11487}
    - mm: add 'try_get_page()' helper function (Linus Torvalds)  [Orabug: 31351941]  {CVE-2019-11487}
    - fs: prevent page refcount overflow in pipe_buf_get (Matthew Wilcox)  [Orabug: 31351941]
    {CVE-2019-11487}
    - mm: make page ref count overflow check tighter and more explicit (Linus Torvalds)  [Orabug: 31351941]
    {CVE-2019-11487}
    - sctp: implement memory accounting on tx path (Xin Long)  [Orabug: 31351960]  {CVE-2019-3874}
    - sunrpc: use SVC_NET() in svcauth_gss_* functions (Vasily Averin)  [Orabug: 31351995]  {CVE-2018-16884}
    - sunrpc: use-after-free in svc_process_common() (Vasily Averin)  [Orabug: 31351995]  {CVE-2018-16884}
    - af_packet: set defaule value for tmo (Mao Wenan)  [Orabug: 31439107]  {CVE-2019-20812}
    - selinux: properly handle multiple messages in selinux_netlink_send() (Paul Moore)  [Orabug: 31439369]
    {CVE-2020-10751}
    - selinux: Print 'sclass' as string when unrecognized netlink message occurs (Marek Milkovic)  [Orabug:
    31439369]  {CVE-2020-10751}
    - mac80211: Do not send Layer 2 Update frame before authorization (Jouni Malinen)  [Orabug: 31473652]
    {CVE-2019-5108}
    - cfg80211/mac80211: make ieee80211_send_layer2_update a public function (Dedy Lansky)  [Orabug: 31473652]
    {CVE-2019-5108}
    - crypto: authenc - fix parsing key with misaligned rta_len (Eric Biggers)  [Orabug: 31535529]
    {CVE-2020-10769}
    - vgacon: Fix for missing check in scrollback handling (Yunhai Zhang)  [Orabug: 31705121]
    {CVE-2020-14331} {CVE-2020-14331}
    - can: peak_usb: pcan_usb_fd: Fix info-leaks to USB devices (Tomas Bortoli)  [Orabug: 31351221]
    {CVE-2019-19535}
    - media: hdpvr: Fix an error handling path in hdpvr_probe() (Arvind Yadav)  [Orabug: 31352053]
    {CVE-2017-16644}
    - fix kABI breakage from 'netns: provide pure entropy for net_hash_mix()' (Dan Duval)  [Orabug: 31351904]
    {CVE-2019-10638} {CVE-2019-10639}
    - netns: provide pure entropy for net_hash_mix() (Eric Dumazet)  [Orabug: 31351904]  {CVE-2019-10638}
    {CVE-2019-10639}
    - fs/binfmt_elf.c: allocate initialized memory in fill_thread_core_info() (Alexander Potapenko)  [Orabug:
    31350639]  {CVE-2020-10732}
    - crypto: user - fix memory leak in crypto_report (Navid Emamdoost)  [Orabug: 31351640]  {CVE-2019-19062}
    - of: unittest: fix memory leak in unittest_data_add (Navid Emamdoost)  [Orabug: 31351702]
    {CVE-2019-19049}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5866.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15505");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-16746");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
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

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['4.1.12-124.43.4.el6uek', '4.1.12-124.43.4.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2020-5866');
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
    {'reference':'kernel-uek-4.1.12-124.43.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.43.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.43.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.43.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.43.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.43.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'},
    {'reference':'kernel-uek-4.1.12-124.43.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.43.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.43.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.43.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.43.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.43.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
