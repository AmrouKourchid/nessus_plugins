#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12611.
##

include('compat.inc');

if (description)
{
  script_id(207000);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2023-52796",
    "CVE-2024-33621",
    "CVE-2024-36015",
    "CVE-2024-36016",
    "CVE-2024-36286",
    "CVE-2024-36484",
    "CVE-2024-37353",
    "CVE-2024-37356",
    "CVE-2024-38549",
    "CVE-2024-38558",
    "CVE-2024-38559",
    "CVE-2024-38560",
    "CVE-2024-38565",
    "CVE-2024-38567",
    "CVE-2024-38578",
    "CVE-2024-38579",
    "CVE-2024-38582",
    "CVE-2024-38583",
    "CVE-2024-38589",
    "CVE-2024-38596",
    "CVE-2024-38599",
    "CVE-2024-38601",
    "CVE-2024-38612",
    "CVE-2024-38613",
    "CVE-2024-38618",
    "CVE-2024-38621",
    "CVE-2024-38627",
    "CVE-2024-38633",
    "CVE-2024-38634",
    "CVE-2024-38637",
    "CVE-2024-38659",
    "CVE-2024-38780",
    "CVE-2024-39276",
    "CVE-2024-39292",
    "CVE-2024-39301",
    "CVE-2024-39475",
    "CVE-2024-39480",
    "CVE-2024-39488",
    "CVE-2024-39489",
    "CVE-2024-40968"
  );

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel (ELSA-2024-12611)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-12611 advisory.

    - MIPS: Octeon: Add PCIe link status check (Dave Kleikamp)  [Orabug: 36952386] {CVE-2024-40968}
    - net: relax socket state check at accept time. (Paolo Abeni) [Orabug: 36768890] {CVE-2024-36484}
    - ext4: fix mb_cache_entry's e_refcnt leak in ext4_xattr_block_cache_find() (Baokun Li) [Orabug: 36774600]
    {CVE-2024-39276}
    - kdb: Use format-strings rather than '- kdb: Fix buffer overflow during tab-complete (Daniel Thompson)
    [Orabug: 36809289] {CVE-2024-39480}
    - net/9p: fix uninit-value in p9_client_rpc() (Nikita Zhandarovich) [Orabug: 36774613] {CVE-2024-39301}
    - fbdev: savage: Handle err return when savagefb_check_var failed (Cai Xinchen) [Orabug: 36809265]
    {CVE-2024-39475}
    - nilfs2: fix use-after-free of timer for log writer thread (Ryusuke Konishi) [Orabug: 36753565]
    {CVE-2024-38583}
    - ALSA: timer: Set lower bound of start tick time (Takashi Iwai) [Orabug: 36753730] {CVE-2024-38618}
    - ipvlan: Dont Use skb->sk in ipvlan_process_v{4,6}_outbound (Yue Haibing) [Orabug: 36763552]
    {CVE-2024-33621}
    - ipvlan: add ipvlan_route_v6_outbound() helper (Eric Dumazet) [Orabug: 36940543] {CVE-2023-52796}
    - enic: Validate length of nl attributes in enic_set_vf_port (Roded Zats) [Orabug: 36763837]
    {CVE-2024-38659}
    - dma-buf/sw-sync: don't enable IRQ from sync_print_obj() (Tetsuo Handa) [Orabug: 36763846]
    {CVE-2024-38780}
    - netfilter: nfnetlink_queue: acquire rcu_read_lock() in instance_destroy_rcu() (Eric Dumazet) [Orabug:
    36763571] {CVE-2024-36286}
    - virtio: delete vq in vp_find_vqs_msix() when request_irq() fails (Jiri Pirko) [Orabug: 36763588]
    {CVE-2024-37353}
    - arm64: asm-bug: Add .align 2 to the end of __BUG_ENTRY (Jiangfeng Xiao) [Orabug: 36825259]
    {CVE-2024-39488}
    - tcp: Fix shift-out-of-bounds in dctcp_update_alpha(). (Kuniyuki Iwashima) [Orabug: 36763592]
    {CVE-2024-37356}
    - ipv6: sr: fix memleak in seg6_hmac_init_algo (Hangbin Liu) [Orabug: 36825263] {CVE-2024-39489}
    - media: stk1160: fix bounds checking in stk1160_copy_video() (Dan Carpenter) [Orabug: 36763603]
    {CVE-2024-38621}
    - um: Add winch to winch_handlers before registering winch IRQ (Roberto Sassu) [Orabug: 36768584]
    {CVE-2024-39292}
    - ppdev: Add an error check in register_device (Huai-Yuan Liu) [Orabug: 36678065] {CVE-2024-36015}
    - stm class: Fix a double free in stm_register_device() (Dan Carpenter) [Orabug: 36763764]
    {CVE-2024-38627}
    - serial: max3100: Update uart_driver_registered on driver removal (Andy Shevchenko) [Orabug: 36763815]
    {CVE-2024-38633}
    - serial: max3100: Lock port->lock when calling uart_handle_cts_change() (Andy Shevchenko) [Orabug:
    36763820] {CVE-2024-38634}
    - greybus: lights: check return of get_channel_from_mode (Rui Miguel Silva) [Orabug: 36763833]
    {CVE-2024-38637}
    - netrom: fix possible dead-lock in nr_rt_ioctl() (Eric Dumazet) [Orabug: 36753582] {CVE-2024-38589}
    - drm/mediatek: Add 0 size check to mtk_drm_gem_obj (Justin Green) [Orabug: 36753415] {CVE-2024-38549}
    - ipv6: sr: fix invalid unregister error path (Hangbin Liu) [Orabug: 36753711] {CVE-2024-38612}
    - net: openvswitch: fix overwriting ct original tuple for ICMPv6 (Ilya Maximets) [Orabug: 36753463]
    {CVE-2024-38558}
    - af_unix: Fix data races in unix_release_sock/unix_stream_sendmsg (Breno Leitao) [Orabug: 36753600]
    {CVE-2024-38596}
    - m68k: Fix spinlock race in kernel thread creation (Michael Schmitz) [Orabug: 36753715] {CVE-2024-38613}
    - scsi: qedf: Ensure the copied buf is NUL terminated (Bui Quang Minh) [Orabug: 36753468] {CVE-2024-38559}
    - scsi: bfa: Ensure the copied buf is NUL terminated (Bui Quang Minh) [Orabug: 36753473] {CVE-2024-38560}
    - wifi: ar5523: enable proper endpoint verification (Nikita Zhandarovich) [Orabug: 36753486]
    {CVE-2024-38565}
    - wifi: carl9170: add a proper sanity check for endpoints (Nikita Zhandarovich) [Orabug: 36753509]
    {CVE-2024-38567}
    - jffs2: prevent xattr node from overflowing the eraseblock (Ilya Denisyev) [Orabug: 36753652]
    {CVE-2024-38599}
    - ecryptfs: Fix buffer size for tag 66 packet (Brian Kubisiak) [Orabug: 36753537] {CVE-2024-38578}
    - crypto: bcm - Fix pointer arithmetic (Aleksandr Mishin) [Orabug: 36753542] {CVE-2024-38579}
    - tty: n_gsm: fix possible out-of-bounds in gsm0_receive() (Daniel Starke) [Orabug: 36678069]
    {CVE-2024-36016}
    - nilfs2: fix potential hang in nilfs_detach_log_writer() (Ryusuke Konishi) [Orabug: 36753558]
    {CVE-2024-38582}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12611.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39480");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7:9:patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::UEKR5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::optional_latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.14.35-2047.540.4.1.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-12611');
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
    {'reference':'kernel-uek-4.14.35-2047.540.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.14.35'},
    {'reference':'kernel-uek-debug-4.14.35-2047.540.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.14.35'},
    {'reference':'kernel-uek-debug-devel-4.14.35-2047.540.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.14.35'},
    {'reference':'kernel-uek-devel-4.14.35-2047.540.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.14.35'},
    {'reference':'kernel-uek-headers-4.14.35-2047.540.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-4.14.35'},
    {'reference':'kernel-uek-tools-4.14.35-2047.540.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-4.14.35'},
    {'reference':'kernel-uek-tools-libs-4.14.35-2047.540.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-4.14.35'},
    {'reference':'kernel-uek-tools-libs-devel-4.14.35-2047.540.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-devel-4.14.35'},
    {'reference':'perf-4.14.35-2047.540.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-4.14.35'},
    {'reference':'python-perf-4.14.35-2047.540.4.1.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-4.14.35'},
    {'reference':'kernel-uek-4.14.35-2047.540.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.14.35'},
    {'reference':'kernel-uek-debug-4.14.35-2047.540.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.14.35'},
    {'reference':'kernel-uek-debug-devel-4.14.35-2047.540.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.14.35'},
    {'reference':'kernel-uek-devel-4.14.35-2047.540.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.14.35'},
    {'reference':'kernel-uek-doc-4.14.35-2047.540.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.14.35'},
    {'reference':'kernel-uek-headers-4.14.35-2047.540.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-4.14.35'},
    {'reference':'kernel-uek-tools-4.14.35-2047.540.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-4.14.35'},
    {'reference':'kernel-uek-tools-libs-4.14.35-2047.540.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-4.14.35'},
    {'reference':'kernel-uek-tools-libs-devel-4.14.35-2047.540.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-devel-4.14.35'},
    {'reference':'perf-4.14.35-2047.540.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-4.14.35'},
    {'reference':'python-perf-4.14.35-2047.540.4.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-4.14.35'}
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
