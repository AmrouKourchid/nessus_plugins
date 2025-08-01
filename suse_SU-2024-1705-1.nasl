#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1705-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(197591);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/13");

  script_cve_id(
    "CVE-2022-48651",
    "CVE-2023-6546",
    "CVE-2023-52502",
    "CVE-2024-26585",
    "CVE-2024-26610",
    "CVE-2024-26766"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1705-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (Live Patch 8 for SLE 15 SP5) (SUSE-SU-2024:1705-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:1705-1 advisory.

  - In the Linux kernel, the following vulnerability has been resolved: ipvlan: Fix out-of-bound bugs caused
    by unset skb->mac_header If an AF_PACKET socket is used to send packets through ipvlan and the default
    xmit function of the AF_PACKET socket is changed from dev_queue_xmit() to packet_direct_xmit() via
    setsockopt() with the option name of PACKET_QDISC_BYPASS, the skb->mac_header may not be reset and remains
    as the initial value of 65535, this may trigger slab-out-of-bounds bugs as following:
    ================================================================= UG: KASAN: slab-out-of-bounds in
    ipvlan_xmit_mode_l2+0xdb/0x330 [ipvlan] PU: 2 PID: 1768 Comm: raw_send Kdump: loaded Not tainted
    6.0.0-rc4+ #6 ardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-1.fc33 all Trace:
    print_address_description.constprop.0+0x1d/0x160 print_report.cold+0x4f/0x112 kasan_report+0xa3/0x130
    ipvlan_xmit_mode_l2+0xdb/0x330 [ipvlan] ipvlan_start_xmit+0x29/0xa0 [ipvlan] __dev_direct_xmit+0x2e2/0x380
    packet_direct_xmit+0x22/0x60 packet_snd+0x7c9/0xc40 sock_sendmsg+0x9a/0xa0 __sys_sendto+0x18a/0x230
    __x64_sys_sendto+0x74/0x90 do_syscall_64+0x3b/0x90 entry_SYSCALL_64_after_hwframe+0x63/0xcd The root cause
    is: 1. packet_snd() only reset skb->mac_header when sock->type is SOCK_RAW and skb->protocol is not
    specified as in packet_parse_headers() 2. packet_direct_xmit() doesn't reset skb->mac_header as
    dev_queue_xmit() In this case, skb->mac_header is 65535 when ipvlan_xmit_mode_l2() is called. So when
    ipvlan_xmit_mode_l2() gets mac header with eth_hdr() which use skb->head + skb->mac_header, out-of-bound
    access occurs. This patch replaces eth_hdr() with skb_eth_hdr() in ipvlan_xmit_mode_l2() and reset mac
    header in multicast to solve this out-of-bound bug. (CVE-2022-48651)

  - In the Linux kernel, the following vulnerability has been resolved: net: nfc: fix races in
    nfc_llcp_sock_get() and nfc_llcp_sock_get_sn() Sili Luo reported a race in nfc_llcp_sock_get(), leading to
    UAF. Getting a reference on the socket found in a lookup while holding a lock should happen before
    releasing the lock. nfc_llcp_sock_get_sn() has a similar problem. Finally nfc_llcp_recv_snl() needs to
    make sure the socket found by nfc_llcp_sock_from_sn() does not disappear. (CVE-2023-52502)

  - A race condition was found in the GSM 0710 tty multiplexor in the Linux kernel. This issue occurs when two
    threads execute the GSMIOC_SETCONF ioctl on the same tty file descriptor with the gsm line discipline
    enabled, and can lead to a use-after-free problem on a struct gsm_dlci while restarting the gsm mux. This
    could allow a local unprivileged user to escalate their privileges on the system. (CVE-2023-6546)

  - In the Linux kernel, the following vulnerability has been resolved: tls: fix race between tx work
    scheduling and socket close Similarly to previous commit, the submitting thread (recvmsg/sendmsg) may exit
    as soon as the async crypto handler calls complete(). Reorder scheduling the work before calling
    complete(). This seems more logical in the first place, as it's the inverse order of what the submitting
    thread will do. (CVE-2024-26585)

  - In the Linux kernel, the following vulnerability has been resolved: wifi: iwlwifi: fix a memory corruption
    iwl_fw_ini_trigger_tlv::data is a pointer to a __le32, which means that if we copy to
    iwl_fw_ini_trigger_tlv::data + offset while offset is in bytes, we'll write past the buffer.
    (CVE-2024-26610)

  - In the Linux kernel, the following vulnerability has been resolved: IB/hfi1: Fix sdma.h tx->num_descs off-
    by-one error Unfortunately the commit `fd8958efe877` introduced another error causing the `descs` array to
    overflow. This reults in further crashes easily reproducible by `sendmsg` system call. [ 1080.836473]
    general protection fault, probably for non-canonical address 0x400300015528b00a: 0000 [#1] PREEMPT SMP PTI
    [ 1080.869326] RIP: 0010:hfi1_ipoib_build_ib_tx_headers.constprop.0+0xe1/0x2b0 [hfi1] -- [ 1080.974535]
    Call Trace: [ 1080.976990] <TASK> [ 1081.021929] hfi1_ipoib_send_dma_common+0x7a/0x2e0 [hfi1] [
    1081.027364] hfi1_ipoib_send_dma_list+0x62/0x270 [hfi1] [ 1081.032633] hfi1_ipoib_send+0x112/0x300 [hfi1]
    [ 1081.042001] ipoib_start_xmit+0x2a9/0x2d0 [ib_ipoib] [ 1081.046978] dev_hard_start_xmit+0xc4/0x210 -- [
    1081.148347] __sys_sendmsg+0x59/0xa0 crash> ipoib_txreq 0xffff9cfeba229f00 struct ipoib_txreq { txreq = {
    list = { next = 0xffff9cfeba229f00, prev = 0xffff9cfeba229f00 }, descp = 0xffff9cfeba229f40, coalesce_buf
    = 0x0, wait = 0xffff9cfea4e69a48, complete = 0xffffffffc0fe0760 <hfi1_ipoib_sdma_complete>, packet_len =
    0x46d, tlen = 0x0, num_desc = 0x0, desc_limit = 0x6, next_descq_idx = 0x45c, coalesce_idx = 0x0, flags =
    0x0, descs = {{ qw = {0x8024000120dffb00, 0x4} # SDMA_DESC0_FIRST_DESC_FLAG (bit 63) }, { qw = {
    0x3800014231b108, 0x4} }, { qw = { 0x310000e4ee0fcf0, 0x8} }, { qw = { 0x3000012e9f8000, 0x8} }, { qw = {
    0x59000dfb9d0000, 0x8} }, { qw = { 0x78000e02e40000, 0x8} }} }, sdma_hdr = 0x400300015528b000, <<< invalid
    pointer in the tx request structure sdma_status = 0x0, SDMA_DESC0_LAST_DESC_FLAG (bit 62) complete = 0x0,
    priv = 0x0, txq = 0xffff9cfea4e69880, skb = 0xffff9d099809f400 } If an SDMA send consists of exactly 6
    descriptors and requires dword padding (in the 7th descriptor), the sdma_txreq descriptor array is not
    properly expanded and the packet will overflow into the container structure. This results in a panic when
    the send completion runs. The exact panic varies depending on what elements of the container structure get
    corrupted. The fix is to use the correct expression in _pad_sdma_tx_descs() to test the need to expand the
    descriptor array. With this patch the crashes are no longer reproducible and the machine is stable.
    (CVE-2024-26766)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223514");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035311.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26585");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26766");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-livepatch-5_14_21-150500_55_39-default package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26610");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150500_55_39-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

var uname_r = get_kb_item("Host/uname-r");
if (empty_or_null(uname_r)) audit(AUDIT_UNKNOWN_APP_VER, "kernel");

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);

var kernel_live_checks = [
  {
    'kernels': {
      '5.14.21-150500.55.39-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_14_21-150500_55_39-default-7-150500.2.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']}
        ]
      }
    }
  }
];

var ltss_caveat_required = FALSE;
var flag = 0;
var kernel_affected = FALSE;
foreach var kernel_array ( kernel_live_checks ) {
  var kpatch_details = kernel_array['kernels'][uname_r];
  if (empty_or_null(kpatch_details)) continue;
  kernel_affected = TRUE;
  foreach var package_array ( kpatch_details['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var exists_check = NULL;
    var rpm_spec_vers_cmp = NULL;
    if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
    if (!empty_or_null(package_array['release'])) _release = package_array['release'];
    if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
    if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
    if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
    if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
    if (reference && _release) {
      if (exists_check) {
        var check_flag = 0;
        foreach var check (exists_check) {
          if (!rpm_exists(release:_release, rpm:check)) continue;
          check_flag++;
        }
        if (!check_flag) continue;
      }
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

# No kpatch details found for the running kernel version
if (!kernel_affected) audit(AUDIT_INST_VER_NOT_VULN, 'kernel', uname_r);

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-livepatch-5_14_21-150500_55_39-default');
}
