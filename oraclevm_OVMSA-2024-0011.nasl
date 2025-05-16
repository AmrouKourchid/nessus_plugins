#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were
# extracted from OracleVM Security Advisory OVMSA-2024-0011.
##

include('compat.inc');

if (description)
{
  script_id(206615);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/15");

  script_cve_id(
    "CVE-2021-46939",
    "CVE-2021-47118",
    "CVE-2021-47153",
    "CVE-2021-47171",
    "CVE-2021-47236",
    "CVE-2021-47284",
    "CVE-2021-47310",
    "CVE-2021-47353",
    "CVE-2021-47356",
    "CVE-2022-48627",
    "CVE-2023-6040",
    "CVE-2023-52445",
    "CVE-2023-52477",
    "CVE-2023-52574",
    "CVE-2023-52594",
    "CVE-2023-52615",
    "CVE-2023-52620",
    "CVE-2023-52628",
    "CVE-2023-52703",
    "CVE-2023-52809",
    "CVE-2023-52881",
    "CVE-2024-26635",
    "CVE-2024-26651",
    "CVE-2024-26675",
    "CVE-2024-26679",
    "CVE-2024-26704",
    "CVE-2024-26772",
    "CVE-2024-26778",
    "CVE-2024-26801",
    "CVE-2024-26805",
    "CVE-2024-26816",
    "CVE-2024-26859",
    "CVE-2024-26880",
    "CVE-2024-26903",
    "CVE-2024-35922",
    "CVE-2024-35944",
    "CVE-2024-35978",
    "CVE-2024-35982",
    "CVE-2024-36016",
    "CVE-2024-36883",
    "CVE-2024-36919",
    "CVE-2024-36950",
    "CVE-2024-36960"
  );

  script_name(english:"OracleVM 3.4 : kernel-uek (OVMSA-2024-0011)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OracleVM host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote OracleVM system is missing necessary patches to address security updates:

    [4.1.12-124.89.4]- isdn: mISDN: netjet: Fix crash in nj_probe: (Zheyu Ma)  [Orabug: 36940405]
    {CVE-2021-47284}- tracing: Restructure trace_clock_global() to never block (Steven Rostedt (VMware))
    [Orabug: 36940388]  {CVE-2021-46939}- udf: Fix NULL pointer dereference in udf_symlink function (Arturo
    Giusti)  [Orabug: 36806640]  {CVE-2021-47353}- media: pvrusb2: fix use after free on context disconnection
    (Ricardo B. Marliere)  [Orabug: 36802294]  {CVE-2023-52445}- vt: fix memory overlapping when deleting
    chars in the buffer (Yangxi Xiang)  [Orabug: 36802212]  {CVE-2022-48627}- tty: n_gsm: fix possible out-of-
    bounds in gsm0_receive() (Daniel Starke)  [Orabug: 36678070]  {CVE-2024-36016}- netfilter: nftables:
    exthdr: fix 4-byte stack OOB write (Florian Westphal)  [Orabug: 36654631]  {CVE-2023-52628}- dm: call the
    resume method on internal suspend (Mikulas Patocka)  [Orabug: 36544879]  {CVE-2024-26880}- net/bnx2x:
    Prevent access to a freed page in page_pool (Thinh Tran)  [Orabug: 36544783]  {CVE-2024-26859}- x86,
    relocs: Ignore relocations in .notes section (Kees Cook)  [Orabug: 36531115]  {CVE-2024-26816}- netlink:
    Fix kernel-infoleak-after-free in __skb_datagram_iter (Ryosuke Yasuoka)  [Orabug: 36531057]
    {CVE-2024-26805}- fbdev: savage: Error out if pixclock equals zero (Fullway Wang)  [Orabug: 36530913]
    {CVE-2024-26778}- ext4: fix double-free of blocks due to wrong extents moved_len (Baokun Li)  [Orabug:
    36530519]  {CVE-2024-26704}- sr9800: Add check for usbnet_get_endpoints (Chen Ni)  [Orabug: 36530183]
    {CVE-2024-26651}- llc: Drop support for ETH_P_TR_802_2. (Kuniyuki Iwashima)  [Orabug: 36530047]
    {CVE-2024-26635}- netfilter: nf_tables: Reject tables of unsupported family (Phil Sutter)  [Orabug:
    36192155]  {CVE-2023-6040}[4.1.12-124.89.3]- wifi: ath9k: Fix potential array-index-out-of-bounds read in
    ath9k_htc_txstatus() (Minsuk Kang)  [Orabug: 36802321]  {CVE-2023-52594}- batman-adv: Avoid infinite loop
    trying to resize local TT (Sven Eckelmann)  [Orabug: 36643464]  {CVE-2024-35982}- Bluetooth: Fix memory
    leak in hci_req_sync_complete() (Dmitry Antipov)  [Orabug: 36643456]  {CVE-2024-35978}- VMCI: Fix memcpy()
    run-time warning in dg_dispatch_as_host() (Harshit Mogalapalli)  [Orabug: 36643323]  {CVE-2024-35944}-
    fbmon: prevent division by zero in fb_videomode_from_videomode() (Roman Smirnov)  [Orabug: 36643194]
    {CVE-2024-35922}[4.1.12-124.89.2]- scsi: libfc: Fix potential NULL pointer dereference in
    fc_lport_ptp_setup() (Wenchao Hao)  [Orabug: 36901390]  {CVE-2023-52809}- net: usb: fix memory leak in
    smsc75xx_bind (Pavel Skripkin)  [Orabug: 36802200]  {CVE-2021-47171}- i2c: i801: Don't generate an
    interrupt on bus reset (Jean Delvare)  [Orabug: 36792714]  {CVE-2021-47153}- pid: take a reference when
    initializing cad_pid (Mark Rutland)  [Orabug: 36792687]  {CVE-2021-47118}- drm/vmwgfx: Fix invalid reads
    in fence signaled events (Zack Rusin)  [Orabug: 36691531]  {CVE-2024-36960}- firewire: ohci: mask bus
    reset interrupts between ISR and bottom half (Adam Goldman)  [Orabug: 36683507]  {CVE-2024-36950}- scsi:
    bnx2fc: Remove spin_lock_bh while releasing resources after upload (Saurav Kashyap)  [Orabug: 36683370]
    {CVE-2024-36919}- net: fix out-of-bounds access in ops_init (Thadeu Lima de Souza Cascardo)  [Orabug:
    36683115]  {CVE-2024-36883}- netfilter: nf_tables: disallow timeout for anonymous sets (Pablo Neira Ayuso)
    [Orabug: 36654625]  {CVE-2023-52620}- team: fix null-ptr-deref when team device type is changed (Ziyang
    Xuan)  [Orabug: 36654606]  {CVE-2023-52574}[4.1.12-124.89.1]- tcp: do not accept ACK of bytes we never
    sent (Eric Dumazet)  [Orabug: 36806731]  {CVE-2023-52881}- net/usb: kalmia: Don't pass act_len in
    usb_bulk_msg error path (Miko Larsson)  [Orabug: 36806698]  {CVE-2023-52703}- hwrng: core - Fix page fault
    dead lock on mmap-ed hwrng (Herbert Xu)  [Orabug: 36806668]  {CVE-2023-52615}- mISDN: fix possible use-
    after-free in HFC_cleanup() (Zou Wei)  [Orabug: 36806645]  {CVE-2021-47356}- net: ti: fix UAF in
    tlan_remove_one (Pavel Skripkin)  [Orabug: 36806628]  {CVE-2021-47310}- net: cdc_eem: fix tx fixup skb
    leak (Linyu Yuan)  [Orabug: 36806622]  {CVE-2021-47236}- usb: hub: Guard against accesses to uninitialized
    BOS descriptors (Ricardo Canuelo)  [Orabug: 36802300]  {CVE-2023-52477}- USB: add quirk for devices with
    broken LPM (Alan Stern)  [Orabug: 36802300]  {CVE-2023-52477}- Bluetooth: rfcomm: Fix null-ptr-deref in
    rfcomm_check_security (Yuxuan Hu)  [Orabug: 36544991]  {CVE-2024-26903}- Bluetooth: Avoid potential use-
    after-free in hci_error_reset (Ying Hsu)  [Orabug: 36531042]  {CVE-2024-26801}- ext4: avoid allocating
    blocks from corrupted group in ext4_mb_find_by_goal() (Baokun Li)  [Orabug: 36530881]  {CVE-2024-26772}-
    inet: read sk->sk_family once in inet_recv_error() (Eric Dumazet)  [Orabug: 36530348]  {CVE-2024-26679}-
    ppp_async: limit MRU to 64K (Eric Dumazet)  [Orabug: 36530335]  {CVE-2024-26675}

Tenable has extracted the preceding description block directly from the OracleVM security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-46939.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-47118.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-47153.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-47171.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-47236.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-47284.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-47310.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-47353.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-47356.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2022-48627.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52445.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52477.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52574.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52594.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52615.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52620.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52628.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52703.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52809.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52881.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-6040.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26635.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26651.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26675.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26679.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26704.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26772.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26778.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26801.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26805.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26816.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26859.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26880.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26903.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-35922.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-35944.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-35978.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-35982.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-36016.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-36883.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-36919.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-36950.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-36960.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/OVMSA-2024-0011.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek / kernel-uek-firmware packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26704");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"OracleVM Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.1.12-124.89.4.el6uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for OVMSA-2024-0011');
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
    {'reference':'kernel-uek-4.1.12-124.89.4.el6uek', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.89.4.el6uek', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
  if (!empty_or_null(package_array['release'])) _release = 'OVS' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-firmware');
}
