#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4060.
##

include('compat.inc');

if (description)
{
  script_id(180975);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2017-18551",
    "CVE-2018-20836",
    "CVE-2019-9454",
    "CVE-2019-9458",
    "CVE-2019-12614",
    "CVE-2019-15217",
    "CVE-2019-15807",
    "CVE-2019-15917",
    "CVE-2019-16231",
    "CVE-2019-16233",
    "CVE-2019-16994",
    "CVE-2019-17053",
    "CVE-2019-17055",
    "CVE-2019-18808",
    "CVE-2019-19046",
    "CVE-2019-19055",
    "CVE-2019-19058",
    "CVE-2019-19059",
    "CVE-2019-19062",
    "CVE-2019-19063",
    "CVE-2019-19332",
    "CVE-2019-19447",
    "CVE-2019-19523",
    "CVE-2019-19524",
    "CVE-2019-19530",
    "CVE-2019-19534",
    "CVE-2019-19537",
    "CVE-2019-19767",
    "CVE-2019-19807",
    "CVE-2019-20054",
    "CVE-2019-20095",
    "CVE-2019-20636",
    "CVE-2020-1749",
    "CVE-2020-2732",
    "CVE-2020-8647",
    "CVE-2020-8649",
    "CVE-2020-9383",
    "CVE-2020-10690",
    "CVE-2020-10732",
    "CVE-2020-10742",
    "CVE-2020-10751",
    "CVE-2020-10942",
    "CVE-2020-11565",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-14305"
  );

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2020-4060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-4060 advisory.

    - [vfio] vfio/pci: Fix SR-IOV VF handling with MMIO blocking (Alex Williamson) [1820632] {CVE-2020-12888}
    - [x86] mm: Fix mremap not considering huge pmd devmap (Rafael Aquini) [1843437] {CVE-2020-10757}
    - [mm] mm, dax: check for pmd_none() after split_huge_pmd() (Rafael Aquini) [1843437] {CVE-2020-10757}
    - [mm] mm: mremap: streamline move_page_tables()s move_huge_pmd() corner case (Rafael Aquini) [1843437]
    {CVE-2020-10757}
    - [mm] mm: mremap: validate input before taking lock (Rafael Aquini) [1843437] {CVE-2020-10757}
    - [wireless] mwifiex: Fix possible buffer overflows in mwifiex_ret_wmm_get_status() (Jarod Wilson)
    [1844070] {CVE-2020-12654}
    - [wireless] mwifiex: Fix possible buffer overflows in mwifiex_cmd_append_vsie_tlv() (Jarod Wilson)
    [1844026] {CVE-2020-12653}
    - [hid] HID: hiddev: do cleanup in failure of opening a device (Torez Smith) [1814257] {CVE-2019-19527}
    - [hid] HID: hiddev: avoid opening a disconnected device (Torez Smith) [1814257] {CVE-2019-19527}
    - [scsi] scsi: sg: add sg_remove_request in sg_write ('Ewan D. Milne') [1840699] {CVE-2020-12770}
    - [fs] fs/binfmt_elf.c: allocate initialized memory in fill_thread_core_info() (Donghai Qiao) [1832062]
    {CVE-2020-10732}
    - [security] selinux: properly handle multiple messages in selinux_netlink_send() (Ondrej Mosnacek)
    [1839650] {CVE-2020-10751}
    - [x86] x86/speculation: Support old struct x86_cpu_id & x86_match_cpu() kABI (Waiman Long) [1827188]
    {CVE-2020-0543}
    - [documentation] x86/speculation: Add Ivy Bridge to affected list (Waiman Long) [1827188] {CVE-2020-0543}
    - [documentation] x86/speculation: Add SRBDS vulnerability and mitigation documentation (Waiman Long)
    [1827188] {CVE-2020-0543}
    - [x86] x86/speculation: Add Special Register Buffer Data Sampling (SRBDS) mitigation (Waiman Long)
    [1827188] {CVE-2020-0543}
    - [x86] x86/cpu: Add 'table' argument to cpu_matches() (Waiman Long) [1827188] {CVE-2020-0543}
    - [x86] x86/cpu: Add a steppings field to struct x86_cpu_id (Waiman Long) [1827188] {CVE-2020-0543}
    - [x86] x86/cpu/bugs: Convert to new matching macros (Waiman Long) [1827188] {CVE-2020-0543}
    - [x86] x86/cpu: Add consistent CPU match macros (Waiman Long) [1827188] {CVE-2020-0543}
    - [cpufreq] x86/devicetable: Move x86 specific macro out of generic code (Waiman Long) [1827188]
    {CVE-2020-0543}
    header (Waiman Long) [1827188] {CVE-2020-0543}
    - [vhost] vhost: Check docket sk_family instead of call getname (Vladis Dronov) [1823302] {CVE-2020-10942}
    - [vfio] vfio-pci: Invalidate mmaps and block MMIO access on disabled memory (Alex Williamson) [1820632]
    {CVE-2020-12888}
    - [vfio] vfio-pci: Fault mmaps to enable vma tracking (Alex Williamson) [1820632] {CVE-2020-12888}
    - [vfio] vfio/type1: Support faulting PFNMAP vmas (Alex Williamson) [1820632] {CVE-2020-12888}
    - [vfio] vfio/type1: Fix VA->PA translation for PFNMAP VMAs in vaddr_get_pfn() (Alex Williamson) [1820632]
    {CVE-2020-12888}
    - [vfio] vfio/pci: call irq_bypass_unregister_producer() before freeing irq (Alex Williamson) [1820632]
    {CVE-2020-12888}
    - [vfio] vfio_pci: Enable memory accesses before calling pci_map_rom (Alex Williamson) [1820632]
    {CVE-2020-12888}
    - [fs] signal: Extend exec_id to 64bits (Chris von Recklinghausen) [1834650] {CVE-2020-12826}
    - [usb] USB: core: Fix races in character device registration and deregistraion (Torez Smith) [1785065]
    {CVE-2019-19537}
    - [usb] usb: cdc-acm: make sure a refcount is taken early enough (Torez Smith) [1802548] {CVE-2019-19530}
    - [usb] USB: adutux: fix use-after-free on disconnect (Torez Smith) [1798822] {CVE-2019-19523}
    - [media] media: usb:zr364xx:Fix KASAN:null-ptr-deref Read in zr364xx_vidioc_querycap (Torez Smith)
    [1795597] {CVE-2019-15217}
    - [fs] ext4: fix support for inode sizes > 1024 bytes (Lukas Czerner) [1817634] {CVE-2019-19767}
    - [fs] ext4: add more paranoia checking in ext4_expand_extra_isize handling (Lukas Czerner) [1817634]
    {CVE-2019-19767}
    - [fs] ext4: forbid i_extra_isize not divisible by 4 (Lukas Czerner) [1817634] {CVE-2019-19767}
    - [fs] ext4: validate the debug_want_extra_isize mount option at parse time (Lukas Czerner) [1817634]
    {CVE-2019-19767}
    - [media] media: v4l: event: Add subscription to list before calling 'add' operation (Jarod Wilson)
    [1828802] {CVE-2019-9458}
    - [media] media: v4l: event: Prevent freeing event subscriptions while accessed (Jarod Wilson) [1828802]
    {CVE-2019-9458}
    - [crypto] crypto: user - fix memory leak in crypto_report (Vladis Dronov) [1825132] {CVE-2019-18808
    CVE-2019-19062}
    - [crypto] crypto: ccp - Release all allocated memory if sha type is invalid (Vladis Dronov) [1825132]
    {CVE-2019-18808}
    - [net] sit: fix memory leak in sit_init_net() (Andrea Claudi) [1830011] {CVE-2019-16994}
    - [netdrv] fjes: Handle workqueue allocation failure (Masayoshi Mizuma) [1830563] {CVE-2019-16231}
    - [mm] mm: mempolicy: require at least one nodeid for MPOL_PREFERRED (Rafael Aquini) [1834434]
    {CVE-2020-11565}
    - [wireless] rtlwifi: prevent memory leak in rtl_usb_probe (Jarod Wilson) [1829847] {CVE-2019-19063}
    - [wireless] iwlwifi: dbg_ini: fix memory leak in alloc_sgtable (Jarod Wilson) [1829375] {CVE-2019-19058}
    - [net] nl80211: fix memory leak in nl80211_get_ftm_responder_stats (Jarod Wilson) [1829289]
    {CVE-2019-19055}
    - [wireless] iwlwifi: pcie: fix memory leaks in iwl_pcie_ctxt_info_gen3_init (Jarod Wilson) [1829393]
    {CVE-2019-19059}
    - [input] Input: add safety guards to input_set_keycode() (Chris von Recklinghausen) [1828222]
    {CVE-2019-20636}
    - [scsi] scsi: libsas: delete sas port if expander discover failed (Tomas Henzl) [1829965]
    {CVE-2019-15807}
    - [net] netlabel: cope with NULL catmap (Paolo Abeni) [1827240] {CVE-2020-10711}
    - [input] Input: ff-memless - kill timer in destroy() (Chris von Recklinghausen) [1815021]
    {CVE-2019-19524}
    - [scsi] scsi: qla2xxx: fix a potential NULL pointer dereference ('Ewan D. Milne') [1829246]
    {CVE-2019-16233}
    - [i2c] i2c: core-smbus: prevent stack corruption on read I2C_BLOCK_DATA (Vladis Dronov) [1822641]
    {CVE-2017-18551}
    - [wireless] mwifiex: Fix mem leak in mwifiex_tm_cmd (Jarod Wilson) [1804971] {CVE-2019-20095}
    - [video] vgacon: Fix a UAF in vgacon_invert_region (Vladis Dronov) [1818730] {CVE-2020-8647
    CVE-2020-8649}
    - [isdn] mISDN: enforce CAP_NET_RAW for raw sockets (Andrea Claudi) [1779474] {CVE-2019-17055}
    - [powerpc] powerpc/pseries/dlpar: Fix a missing check in dlpar_parse_cc_property() (Steve Best) [1806629]
    {CVE-2019-12614}
    - [block] floppy: check FDC index for errors before assigning it (Ming Lei) [1815403] {CVE-2020-9383}
    - [char] ipmi: Fix memory leak in __ipmi_bmc_register (Tony Camuso) [1812836] {CVE-2019-19046}
    - [bluetooth] Bluetooth: hci_ldisc: Postpone HCI_UART_PROTO_READY bit set in hci_uart_set_proto() (Aristeu
    Rozanski) [1808803] {CVE-2019-15917}
    - [x86] kvm: x86: clear stale x86_emulate_ctxt->intercept value (Jon Maloy) [1806818] {CVE-2020-2732}
    - [x86] kvm: vmx: check descriptor table exits on instruction emulation (Jon Maloy) [1806818]
    {CVE-2020-2732}
    - [x86] kvm: nvmx: Check IO instruction VM-exit conditions (Jon Maloy) [1806818] {CVE-2020-2732}
    - [x86] kvm: nvmx: Refactor IO bitmap checks into helper function (Jon Maloy) [1806818] {CVE-2020-2732}
    - [x86] kvm: nvmx: Dont emulate instructions in guest mode (Jon Maloy) [1806818] {CVE-2020-2732}
    - [net] ipv6_stub: use ip6_dst_lookup_flow instead of ip6_dst_lookup (Sabrina Dubroca) [1774447]
    {CVE-2020-1749}
    - [net] ipv6: add net argument to ip6_dst_lookup_flow (Sabrina Dubroca) [1774447] {CVE-2020-1749}
    - [net] ipv6: constify ip6_dst_lookup_{flow|tail}() sock arguments (Sabrina Dubroca) [1774447]
    {CVE-2020-1749}
    - [net] ieee802154: enforce CAP_NET_RAW for raw sockets (Andrea Claudi) [1779494] {CVE-2019-17053}
    - [kernel] blktrace: fix dereference after null check (Ming Lei) [1798318] {CVE-2019-19768}
    - [kernel] blktrace: Protect q->blk_trace with RCU (Ming Lei) [1798318] {CVE-2019-19768}
    - [kernel] blktrace: fix trace mutex deadlock (Ming Lei) [1798318] {CVE-2019-19768}
    - [kernel] blktrace: fix unlocked registration of tracepoints (Ming Lei) [1798318] {CVE-2019-19768}
    - [kernel] blktrace: fix unlocked access to init/start-stop/teardown (Ming Lei) [1798318] {CVE-2019-19768}
    - [sound] ALSA: timer: Fix incorrectly assigned timer instance (Jaroslav Kysela) [1798457]
    {CVE-2019-19807}
    - [x86] kvm: OOB memory write via kvm_dev_ioctl_get_cpuid (CVE-2019-19332) (Philippe Mathieu-Daud)
    [1783455] {CVE-2019-19332}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-4060.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20836");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14305");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['3.10.0-1160.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2020-4060');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '3.10';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / etc');
}
