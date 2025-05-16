#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2805-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(178180);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/14");

  script_cve_id(
    "CVE-2017-5753",
    "CVE-2018-20784",
    "CVE-2022-3566",
    "CVE-2022-45884",
    "CVE-2022-45885",
    "CVE-2022-45886",
    "CVE-2022-45887",
    "CVE-2022-45919",
    "CVE-2023-0590",
    "CVE-2023-1077",
    "CVE-2023-1095",
    "CVE-2023-1118",
    "CVE-2023-1249",
    "CVE-2023-1380",
    "CVE-2023-1390",
    "CVE-2023-1513",
    "CVE-2023-1611",
    "CVE-2023-1670",
    "CVE-2023-1989",
    "CVE-2023-1990",
    "CVE-2023-1998",
    "CVE-2023-2124",
    "CVE-2023-2162",
    "CVE-2023-2194",
    "CVE-2023-2513",
    "CVE-2023-3090",
    "CVE-2023-3141",
    "CVE-2023-3159",
    "CVE-2023-3161",
    "CVE-2023-23454",
    "CVE-2023-23455",
    "CVE-2023-28328",
    "CVE-2023-28464",
    "CVE-2023-28772",
    "CVE-2023-30772",
    "CVE-2023-31436",
    "CVE-2023-32269",
    "CVE-2023-35824"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2805-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2023:2805-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2023:2805-1 advisory.

  - Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized
    disclosure of information to an attacker with local user access via a side-channel analysis.
    (CVE-2017-5753)

  - In the Linux kernel before 4.20.2, kernel/sched/fair.c mishandles leaf cfs_rq's, which allows attackers to
    cause a denial of service (infinite loop in update_blocked_averages) or possibly have unspecified other
    impact by inducing a high load. (CVE-2018-20784)

  - A vulnerability, which was classified as problematic, was found in Linux Kernel. This affects the function
    tcp_getsockopt/tcp_setsockopt of the component TCP Handler. The manipulation leads to race condition. It
    is recommended to apply a patch to fix this issue. The identifier VDB-211089 was assigned to this
    vulnerability. (CVE-2022-3566)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvbdev.c has a use-
    after-free, related to dvb_register_device dynamically allocating fops. (CVE-2022-45884)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvb_frontend.c has a
    race condition that can cause a use-after-free when a device is disconnected. (CVE-2022-45885)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvb_net.c has a
    .disconnect versus dvb_device_open race condition that leads to a use-after-free. (CVE-2022-45886)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/usb/ttusb-dec/ttusb_dec.c has a
    memory leak because of the lack of a dvb_frontend_detach call. (CVE-2022-45887)

  - An issue was discovered in the Linux kernel through 6.0.10. In drivers/media/dvb-core/dvb_ca_en50221.c, a
    use-after-free can occur is there is a disconnect after an open, because of the lack of a wait_event.
    (CVE-2022-45919)

  - A use-after-free flaw was found in qdisc_graft in net/sched/sch_api.c in the Linux Kernel due to a race
    problem. This flaw leads to a denial of service issue. If patch ebda44da44f6 (net: sched: fix race
    condition in qdisc_graft()) not applied yet, then kernel could be affected. (CVE-2023-0590)

  - In the Linux kernel, pick_next_rt_entity() may return a type confused entry, not detected by the BUG_ON
    condition, as the confused entry will not be NULL, but list_head.The buggy error condition would lead to a
    type confused entry with the list head,which would then be used as a type confused sched_rt_entity,causing
    memory corruption. (CVE-2023-1077)

  - In nf_tables_updtable, if nf_tables_table_enable returns an error, nft_trans_destroy is called to free the
    transaction object. nft_trans_destroy() calls list_del(), but the transaction was never placed on a list
    -- the list head is all zeroes, this results in a NULL pointer dereference. (CVE-2023-1095)

  - A flaw use after free in the Linux kernel integrated infrared receiver/transceiver driver was found in the
    way user detaching rc device. A local user could use this flaw to crash the system or potentially escalate
    their privileges on the system. (CVE-2023-1118)

  - A use-after-free flaw was found in the Linux kernel's core dump subsystem. This flaw allows a local user
    to crash the system. Only if patch 390031c94211 (coredump: Use the vma snapshot in fill_files_note) not
    applied yet, then kernel could be affected. (CVE-2023-1249)

  - A slab-out-of-bound read problem was found in brcmf_get_assoc_ies in
    drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c in the Linux Kernel. This issue could occur
    when assoc_info->req_len data is bigger than the size of the buffer, defined as WL_EXTRA_BUF_MAX, leading
    to a denial of service. (CVE-2023-1380)

  - A remote denial of service vulnerability was found in the Linux kernel's TIPC kernel module. The while
    loop in tipc_link_xmit() hits an unknown state while attempting to parse SKBs, which are not in the queue.
    Sending two small UDP packets to a system with a UDP bearer results in the CPU utilization for the system
    to instantly spike to 100%, causing a denial of service condition. (CVE-2023-1390)

  - A flaw was found in KVM. When calling the KVM_GET_DEBUGREGS ioctl, on 32-bit systems, there might be some
    uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an
    information leak. (CVE-2023-1513)

  - A use-after-free flaw was found in btrfs_search_slot in fs/btrfs/ctree.c in btrfs in the Linux Kernel.This
    flaw allows an attacker to crash the system and possibly cause a kernel information lea (CVE-2023-1611)

  - A flaw use after free in the Linux kernel Xircom 16-bit PCMCIA (PC-card) Ethernet driver was found.A local
    user could use this flaw to crash the system or potentially escalate their privileges on the system.
    (CVE-2023-1670)

  - A use-after-free flaw was found in btsdio_remove in drivers\bluetooth\btsdio.c in the Linux Kernel. In
    this flaw, a call to btsdio_remove with an unfinished job, may cause a race problem leading to a UAF on
    hdev devices. (CVE-2023-1989)

  - A use-after-free flaw was found in ndlc_remove in drivers/nfc/st-nci/ndlc.c in the Linux Kernel. This flaw
    could allow an attacker to crash the system due to a race problem. (CVE-2023-1990)

  - The Linux kernel allows userspace processes to enable mitigations by calling prctl with
    PR_SET_SPECULATION_CTRL which disables the speculation feature as well as by using seccomp. We had noticed
    that on VMs of at least one major cloud provider, the kernel still left the victim process exposed to
    attacks in some cases even after enabling the spectre-BTI mitigation with prctl. The same behavior can be
    observed on a bare-metal machine when forcing the mitigation to IBRS on boot command line. This happened
    because when plain IBRS was enabled (not enhanced IBRS), the kernel had some logic that determined that
    STIBP was not needed. The IBRS bit implicitly protects against cross-thread branch target injection.
    However, with legacy IBRS, the IBRS bit was cleared on returning to userspace, due to performance reasons,
    which disabled the implicit STIBP and left userspace threads vulnerable to cross-thread branch target
    injection against which STIBP protects. (CVE-2023-1998)

  - An out-of-bounds memory access flaw was found in the Linux kernel's XFS file system in how a user restores
    an XFS image after failure (with a dirty log journal). This flaw allows a local user to crash or
    potentially escalate their privileges on the system. (CVE-2023-2124)

  - A use-after-free vulnerability was found in iscsi_sw_tcp_session_create in drivers/scsi/iscsi_tcp.c in
    SCSI sub-component in the Linux Kernel. In this flaw an attacker could leak kernel internal information.
    (CVE-2023-2162)

  - An out-of-bounds write vulnerability was found in the Linux kernel's SLIMpro I2C device driver. The
    userspace data->block[0] variable was not capped to a number between 0-255 and was used as the size of a
    memcpy, possibly writing beyond the end of dma_buffer. This flaw could allow a local privileged user to
    crash the system or potentially achieve code execution. (CVE-2023-2194)

  - cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes
    indicate a TC_ACT_SHOT condition rather than valid classification results). (CVE-2023-23454)

  - atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition
    rather than valid classification results). (CVE-2023-23455)

  - A use-after-free vulnerability was found in the Linux kernel's ext4 filesystem in the way it handled the
    extra inode size for extended attributes. This flaw could allow a privileged local user to cause a system
    crash or other undefined behaviors. (CVE-2023-2513)

  - A NULL pointer dereference flaw was found in the az6027 driver in drivers/media/usb/dev-usb/az6027.c in
    the Linux Kernel. The message from user space is not checked properly before transferring into the device.
    This flaw allows a local user to crash the system or potentially cause a denial of service.
    (CVE-2023-28328)

  - hci_conn_cleanup in net/bluetooth/hci_conn.c in the Linux kernel through 6.2.9 has a use-after-free
    (observed in hci_conn_hash_flush) because of calls to hci_dev_put and hci_conn_put. There is a double free
    that may lead to privilege escalation. (CVE-2023-28464)

  - An issue was discovered in the Linux kernel before 5.13.3. lib/seq_buf.c has a seq_buf_putmem_hex buffer
    overflow. (CVE-2023-28772)

  - The Linux kernel before 6.2.9 has a race condition and resultant use-after-free in
    drivers/power/supply/da9150-charger.c if a physically proximate attacker unplugs a device.
    (CVE-2023-30772)

  - A heap out-of-bounds write vulnerability in the Linux Kernel ipvlan network driver can be exploited to
    achieve local privilege escalation. The out-of-bounds write is caused by missing skb->cb initialization in
    the ipvlan network driver. The vulnerability is reachable if CONFIG_IPVLAN is enabled. We recommend
    upgrading past commit 90cbed5247439a966b645b34eb0a2e037836ea8e. (CVE-2023-3090)

  - A use-after-free flaw was found in r592_remove in drivers/memstick/host/r592.c in media access in the
    Linux Kernel. This flaw allows a local attacker to crash the system at device disconnect, possibly leading
    to a kernel information leak. (CVE-2023-3141)

  - qfq_change_class in net/sched/sch_qfq.c in the Linux kernel before 6.2.13 allows an out-of-bounds write
    because lmax can exceed QFQ_MIN_LMAX. (CVE-2023-31436)

  - A use after free issue was discovered in driver/firewire in outbound_phy_packet_callback in the Linux
    Kernel. In this flaw a local attacker with special privilege may cause a use after free problem when
    queue_event() fails. (CVE-2023-3159)

  - A flaw was found in the Framebuffer Console (fbcon) in the Linux Kernel. When providing font->width and
    font->height greater than 32 to fbcon_set_font, since there are no checks in place, a shift-out-of-bounds
    occurs leading to undefined behavior and possible denial of service. (CVE-2023-3161)

  - An issue was discovered in the Linux kernel before 6.1.11. In net/netrom/af_netrom.c, there is a use-
    after-free because accept is also allowed for a successfully connected AF_NETROM socket. However, in order
    for an attacker to exploit this, the system must have netrom routing configured or the attacker must have
    the CAP_NET_ADMIN capability. (CVE-2023-32269)

  - An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in dm1105_remove in
    drivers/media/pci/dm1105/dm1105.c. (CVE-2023-35824)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1118");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1249");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1380");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1390");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1513");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2194");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23454");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23455");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2513");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28328");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28464");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-31436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-32269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35824");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-July/015468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78f2c5aa");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20784");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-4.4.121-92.205.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'kernel-default-base-4.4.121-92.205.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'kernel-default-devel-4.4.121-92.205.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'kernel-devel-4.4.121-92.205.1', 'sp':'2', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'kernel-macros-4.4.121-92.205.1', 'sp':'2', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'kernel-source-4.4.121-92.205.1', 'sp':'2', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'kernel-syms-4.4.121-92.205.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
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
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-default / kernel-default-base / kernel-default-devel / etc');
}
