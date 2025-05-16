#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207620);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/25");

  script_cve_id(
    "CVE-2019-25162",
    "CVE-2021-33631",
    "CVE-2021-46904",
    "CVE-2021-46905",
    "CVE-2021-46906",
    "CVE-2021-46915",
    "CVE-2021-46921",
    "CVE-2021-46928",
    "CVE-2021-46932",
    "CVE-2021-46934",
    "CVE-2021-46936",
    "CVE-2021-46938",
    "CVE-2021-46939",
    "CVE-2021-46945",
    "CVE-2021-46952",
    "CVE-2021-46953",
    "CVE-2021-46955",
    "CVE-2021-46960",
    "CVE-2021-46988",
    "CVE-2021-46992",
    "CVE-2021-47006",
    "CVE-2021-47010",
    "CVE-2021-47013",
    "CVE-2021-47015",
    "CVE-2021-47024",
    "CVE-2021-47054",
    "CVE-2021-47060",
    "CVE-2021-47061",
    "CVE-2021-47063",
    "CVE-2021-47074",
    "CVE-2021-47076",
    "CVE-2021-47077",
    "CVE-2021-47078",
    "CVE-2021-47082",
    "CVE-2021-47091",
    "CVE-2021-47101",
    "CVE-2021-47131",
    "CVE-2021-47142",
    "CVE-2021-47144",
    "CVE-2021-47146",
    "CVE-2021-47166",
    "CVE-2021-47167",
    "CVE-2021-47168",
    "CVE-2021-47170",
    "CVE-2021-47171",
    "CVE-2021-47182",
    "CVE-2021-47194",
    "CVE-2021-47203",
    "CVE-2022-48619",
    "CVE-2022-48627",
    "CVE-2023-7042",
    "CVE-2023-51042",
    "CVE-2023-51043",
    "CVE-2023-52340",
    "CVE-2023-52435",
    "CVE-2023-52439",
    "CVE-2023-52458",
    "CVE-2023-52464",
    "CVE-2023-52469",
    "CVE-2023-52477",
    "CVE-2023-52478",
    "CVE-2023-52486",
    "CVE-2023-52515",
    "CVE-2023-52522",
    "CVE-2023-52527",
    "CVE-2023-52528",
    "CVE-2023-52530",
    "CVE-2023-52574",
    "CVE-2023-52578",
    "CVE-2023-52583",
    "CVE-2023-52587",
    "CVE-2023-52595",
    "CVE-2023-52597",
    "CVE-2023-52612",
    "CVE-2023-52615",
    "CVE-2023-52619",
    "CVE-2023-52620",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2024-0607",
    "CVE-2024-0775",
    "CVE-2024-1086",
    "CVE-2024-1151",
    "CVE-2024-23307",
    "CVE-2024-24855",
    "CVE-2024-25739",
    "CVE-2024-26597",
    "CVE-2024-26598",
    "CVE-2024-26602",
    "CVE-2024-26614",
    "CVE-2024-26633",
    "CVE-2024-26635",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26642",
    "CVE-2024-26645",
    "CVE-2024-26668",
    "CVE-2024-26671",
    "CVE-2024-26675",
    "CVE-2024-26679",
    "CVE-2024-26686",
    "CVE-2024-26704",
    "CVE-2024-26720",
    "CVE-2024-26733",
    "CVE-2024-26735",
    "CVE-2024-26739",
    "CVE-2024-26740",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26752",
    "CVE-2024-26759",
    "CVE-2024-26763",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26779",
    "CVE-2024-26804",
    "CVE-2024-26805",
    "CVE-2024-26810",
    "CVE-2024-26812",
    "CVE-2024-26813",
    "CVE-2024-26828",
    "CVE-2024-26840",
    "CVE-2024-26845",
    "CVE-2024-26851",
    "CVE-2024-26859",
    "CVE-2024-26872",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26894",
    "CVE-2024-26901",
    "CVE-2024-26915",
    "CVE-2024-26922",
    "CVE-2024-27437"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/20");

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2024-2476)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    IB/ipoib: Fix mcast list locking(CVE-2023-52587)

    netfilter: nftables: avoid overflows in nft_hash_buckets()(CVE-2021-46992)

    SUNRPC: Fix a suspicious RCU usage warning(CVE-2023-52623)

    l2tp: pass correct message length to ip6_append_data(CVE-2024-26752)

    net/sched: act_mirred: use the backlog for mirred ingress(CVE-2024-26740)

    RDMA/srp: Do not call scsi_done() from srp_abort()(CVE-2023-52515)

    hwrng: core - Fix page fault dead lock on mmap-ed hwrng(CVE-2023-52615)

    KVM: s390: fix setting of fpc register(CVE-2023-52597)

    In the Linux kernel before 6.4.5, drivers/gpu/drm/drm_atomic.c has a use-after-free during a race
    condition between a nonblocking atomic commit and a driver unload.(CVE-2023-51043)

    uio: Fix use-after-free in uio_open(CVE-2023-52439)

    A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation.The nft_verdict_init() function allows positive values as drop error
    within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when
    NF_DROP is issued with a drop error which resembles NF_ACCEPT.(CVE-2024-1086)

    ACPI: GTDT: Don't corrupt interrupt mappings on watchdow probe failure(CVE-2021-46953)

    drivers/amd/pm: fix a use-after-free in kv_parse_power_table(CVE-2023-52469)

    KVM: Destroy I/O bus devices on unregister failure _after_ sync'ing SRCU(CVE-2021-47061)

    KVM: arm64: vgic-its: Avoid potential UAF in LPI translation cache(CVE-2024-26598)

    i2c: validate user data in compat ioctl(CVE-2021-46934)

    parisc: Clear stale IIR value on instruction access rights trap(CVE-2021-46928)

    net: hso: fix null-ptr-deref during tty device unregistration(CVE-2021-46904)

    net: hso: fix NULL-deref on disconnect regression(CVE-2021-46905)

    usb: hub: Guard against accesses to uninitialized BOS descriptors(CVE-2023-52477)

    EDAC/thunderx: Fix possible out-of-bounds string access(CVE-2023-52464)

    cifs: Return correct error code from smb2_get_enc_key(CVE-2021-46960)

    openvswitch: fix stack OOB read while fragmenting IPv4 packets(CVE-2021-46955)

    ceph: fix deadlock or deadcode of misusing dget()(CVE-2023-52583)

    ARM: 9064/1: hw_breakpoint: Do not directly check the event's overflow_handler hook(CVE-2021-47006)

    block: add check that partition length needs to be aligned with block size(CVE-2023-52458)

    locking/qrwlock: Fix ordering in queued_write_lock_slowpath()(CVE-2021-46921)

    The IPv6 implementation in the Linux kernel before 6.3 has a net/ipv6/route.c max_size threshold that can
    be consumed easily, e.g., leading to a denial of service (network is unreachable errors) when IPv6 packets
    are sent in a loop via a raw socket.(CVE-2023-52340)

    pstore/ram: Fix crash when setting number of cpus to an odd number(CVE-2023-52619)

    NFS: fs_context: validate UDP retrans to prevent shift out-of-bounds(CVE-2021-46952)

    ext4: always panic when errors=panic is specified(CVE-2021-46945)

    net: fix possible store tearing in neigh_periodic_work()(CVE-2023-52522)

    net:emac/emac-mac: Fix a use after free in emac_mac_tx_buf_send(CVE-2021-47013)

    bnxt_en: Fix RX consumer index logic in the error path.(CVE-2021-47015)

    net: Only allow init netns to set default tcp cong to a restricted algo(CVE-2021-47010)

    net: usb: smsc75xx: Fix uninit-value access in __smsc75xx_read_reg(CVE-2023-52528)

    A race condition was found in the Linux kernel's scsi device driver in lpfc_unregister_fcf_rescan()
    function. This can result in a null pointer dereference issue, possibly leading to a kernel panic or
    denial of service issue.(CVE-2024-24855)

    ext4: avoid online resizing failures due to oversized flex bg(CVE-2023-52622)

    nvme-loop: fix memory leak in nvme_loop_create_ctrl()(CVE-2021-47074)

    userfaultfd: release page in error path to avoid BUG_ON(CVE-2021-46988)

    A use-after-free flaw was found in the __ext4_remount in fs/ext4/super.c in ext4 in the Linux kernel. This
    flaw allows a local user to cause an information leak problem while freeing the old quota file names
    before a potential failure, leading to a use-after-free.(CVE-2024-0775)

    Integer Overflow or Wraparound vulnerability in openEuler kernel on Linux (filesystem modules) allows
    Forced Integer Overflow.This issue affects openEuler kernel: from 4.19.90 before 4.19.90-2401.3, from
    5.10.0-60.18.0 before 5.10.0-183.0.0.(CVE-2021-33631)

    NFS: Fix an Oopsable condition in __nfs_pageio_add_request()(CVE-2021-47167)

    crypto: scomp - fix req-dst buffer overflow(CVE-2023-52612)

    sched/membarrier: reduce the ability to hammer on sys_membarrier(CVE-2024-26602)

    Integer Overflow or Wraparound vulnerability in Linux Linux kernel kernel on Linux, x86, ARM (md, raid,
    raid5 modules) allows Forced Integer Overflow.(CVE-2024-23307)

    dm rq: fix double free of blk_mq_tag_set in dev remove after table load fails(CVE-2021-46938)

    NFS: Don't corrupt the value of pg_bytes_written in nfs_do_recoalesce()(CVE-2021-47166)

    drm: Don't unref the same fb many times by mistake due to deadlock handling(CVE-2023-52486)

    A flaw was found in the Netfilter subsystem in the Linux kernel. The issue is in the nft_byteorder_eval()
    function, where the code iterates through a loop and writes to the `dst` array. On each iteration, 8 bytes
    are written, but `dst` is an array of u32, so each element only has space for 4 bytes. That means every
    iteration overwrites part of the previous element corrupting this array of u32. This flaw allows a local
    user to cause a denial of service or potentially break NetFilter functionality.(CVE-2024-0607)

    blk-mq: fix IO hang from sbitmap wakeup race(CVE-2024-26671)

    i2c: Fix a potential use after free(CVE-2019-25162)

    drm: bridge/panel: Cleanup connector on bridge detach(CVE-2021-47063)

    bus: qcom: Put child node before return(CVE-2021-47054)

    A vulnerability was reported in the Open vSwitch sub-component in the Linux Kernel. The flaw occurs when a
    recursive operation of code push recursively calls into the code block. The OVS module does not validate
    the stack depth, pushing too many frames and causing a stack overflow. As a result, this can lead to a
    crash or other related issues.(CVE-2024-1151)

    net: prevent mss overflow in skb_segment()(CVE-2023-52435)

    RDMA/rxe: Return CQE error if invalid lkey was supplied(CVE-2021-47076)

    ipv4, ipv6: Fix handling of transhdrlen in __ip{,6}_append_data()(CVE-2023-52527)

    netfilter: nft_limit: avoid possible divide error in nft_limit_init(CVE-2021-46915)

    ipv6: sr: fix possible use-after-free and null-ptr-deref(CVE-2024-26735)

    netfilter: nf_tables: disallow anonymous set with timeout flag(CVE-2024-26642)

    drm/amdgpu: Fix a use-after-free(CVE-2021-47142)

    tcp: add sanity checks to rx zerocopy(CVE-2024-26640)

    USB: usbfs: Don't WARN about excessively large memory allocations(CVE-2021-47170)

    net: usb: fix memory leak in smsc75xx_bind(CVE-2021-47171)

    tracing: Ensure visibility when inserting an element into tracing_map(CVE-2024-26645)

    mld: fix panic in mld_newpack()(CVE-2021-47146)

    llc: Drop support for ETH_P_TR_802_2.(CVE-2024-26635)

    inet: read sk-sk_family once in inet_recv_error()(CVE-2024-26679)

    asix: fix uninit-value in asix_mdio_read()(CVE-2021-47101)

    mac80211: fix locking in ieee80211_start_ap error path(CVE-2021-47091)

    ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim()(CVE-2024-26633)

    ext4: avoid allocating blocks from corrupted group in ext4_mb_find_by_goal()(CVE-2024-26772)

    wifi: mac80211: fix race condition on enabling fast-xmit(CVE-2024-26779)

    NFS: fix an incorrect limit in filelayout_decode_layout()(CVE-2021-47168)

    net: ip_tunnel: prevent perpetual headroom growth(CVE-2024-26804)

    mm/swap: fix race when skipping swapcache(CVE-2024-26759)

    mm/writeback: fix possible divide-by-zero in wb_dirty_limits(), again(CVE-2024-26720)

    ext4: avoid allocating blocks from corrupted group in ext4_mb_try_best_found()(CVE-2024-26773)

    dm-crypt: don't modify the data when using authenticated encryption(CVE-2024-26763)

    netlink: Fix kernel-infoleak-after-free in __skb_datagram_iter(CVE-2024-26805)

    net/tls: Fix use-after-free after the TLS device goes down and up(CVE-2021-47131)

    netfilter: nf_tables: disallow timeout for anonymous sets(CVE-2023-52620)

    vt: fix memory overlapping when deleting chars in the buffer(CVE-2022-48627)

    wifi: mac80211: fix potential key use-after-free(CVE-2023-52530)

    net: bridge: use DEV_STATS_INC()(CVE-2023-52578)

    RDMA/rxe: Clear all QP fields if creation failed(CVE-2021-47078)

    Input: appletouch - initialize work before device registration(CVE-2021-46932)

    In the Linux kernel before 6.4.12, amdgpu_cs_wait_all_fences in drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c has
    a fence use-after-free.(CVE-2023-51042)

    An issue was discovered in drivers/input/input.c in the Linux kernel before 5.17.10. An attacker can cause
    a denial of service (panic) because input_set_capability mishandles the situation in which an event code
    falls outside of a bitmap.(CVE-2022-48619)

    vsock/virtio: free queued packets when closing socket(CVE-2021-47024)

    net: fix use-after-free in tw_timer_handler(CVE-2021-46936)

    scsi: qedf: Add pointer checks in qedf_update_link_speed()(CVE-2021-47077)

    scsi: lpfc: Fix list_add() corruption in lpfc_drain_txq()(CVE-2021-47203)

    HID: logitech-hidpp: Fix kernel crash on receiver USB disconnect(CVE-2023-52478)

    arp: Prevent overflow in arp_req_get().(CVE-2024-26733)

    RDMA/qedr: Fix qedr_create_user_qp error flow(CVE-2024-26743)

    RDMA/srpt: Support specifying the srpt_service_guid parameter(CVE-2024-26744)

    ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv()(CVE-2024-26641)

    fs/proc: do_task_stat: use sig-stats_lock to gather the threads/children stats(CVE-2024-26686)

    ppp_async: limit MRU to 64K(CVE-2024-26675)

    create_empty_lvol in drivers/mtd/ubi/vtbl.c in the Linux kernel through 6.7.4 can attempt to allocate zero
    bytes, and crash, because of a missing check for ubi-leb_size.(CVE-2024-25739)

    KVM: Stop looking for coalesced MMIO zones if the bus is destroyed(CVE-2021-47060)

    net/sched: act_mirred: don't override retval if we already lost the skb(CVE-2024-26739)

    HID: usbhid: fix info leak in hid_submit_ctrl(CVE-2021-46906)

    bpf: Fix hashtab overflow check on 32-bit arches(CVE-2024-26884)

    drm/amd/amdgpu: fix refcount leak(CVE-2021-47144)

    tracing: Restructure trace_clock_global() to never block(CVE-2021-46939)

    netfilter: nft_limit: reject configurations that cause integer overflow(CVE-2024-26668)

    ACPI: processor_idle: Fix memory leak in acpi_processor_power_exit()(CVE-2024-26894)

    ext4: fix double-free of blocks due to wrong extents moved_len(CVE-2024-26704)

    netfilter: nf_conntrack_h323: Add protection for bmp length out of range(CVE-2024-26851)

    vfio/pci: Lock external INTx masking ops(CVE-2024-26810)

    cfg80211: call cfg80211_stop_ap when switch from P2P_GO type(CVE-2021-47194)

    vfio/pci: Disable auto-enable of exclusive INTx IRQ(CVE-2024-27437)

    RDMA/srpt: Do not register event handler until srpt device is fully setup(CVE-2024-26872)

    cachefiles: fix memory leak in cachefiles_add_cache()(CVE-2024-26840)

    drm/amdgpu: Reset IH OVERFLOW_CLEAR bit(CVE-2024-26915)

    vfio/platform: Create persistent IRQ handlers(CVE-2024-26813)

    net: ip_tunnel: make sure to pull inner header in ip_tunnel_rcv()(CVE-2024-26882)

    net/bnx2x: Prevent access to a freed page in page_pool(CVE-2024-26859)

    vfio/pci: Create persistent INTx handler(CVE-2024-26812)

    team: fix null-ptr-deref when team device type is changed(CVE-2023-52574)

    drm/amdgpu: validate the parameters of bo mapping operations more clearly(CVE-2024-26922)

    cifs: fix underflow in parse_server_interfaces()(CVE-2024-26828)

    do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak(CVE-2024-26901)

    scsi: core: Fix scsi_mode_sense() buffer length handling(CVE-2021-47182)

    A null pointer dereference vulnerability was found in ath10k_wmi_tlv_op_pull_mgmt_tx_compl_ev() in
    drivers/net/wireless/ath/ath10k/wmi-tlv.c in the Linux kernel. This issue could be exploited to trigger a
    denial of service.(CVE-2023-7042)

    net: qualcomm: rmnet: fix global oob in rmnet_policy(CVE-2024-26597)

    tun: avoid double free in tun_free_netdev(CVE-2021-47082)

    scsi: target: core: Add TMF to tmr_list handling(CVE-2024-26845)

    bpf: Fix stackmap overflow check on 32-bit arches(CVE-2024-26883)

    tcp: make sure init the accept_queue's spinlocks once(CVE-2024-26614)

    wifi: rt2x00: restart beacon queue when hardware reset(CVE-2023-52595)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2476
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f561887");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26884");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "kernel-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "kernel-devel-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "kernel-headers-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "kernel-tools-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "kernel-tools-libs-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "perf-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "python-perf-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8",
  "python3-perf-4.19.36-vhulk1907.1.0.h1635.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
