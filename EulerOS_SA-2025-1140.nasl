#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216020);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2022-48868",
    "CVE-2022-48916",
    "CVE-2022-48961",
    "CVE-2022-48975",
    "CVE-2023-52917",
    "CVE-2023-52920",
    "CVE-2024-43817",
    "CVE-2024-44958",
    "CVE-2024-46678",
    "CVE-2024-46714",
    "CVE-2024-46765",
    "CVE-2024-46830",
    "CVE-2024-47668",
    "CVE-2024-47674",
    "CVE-2024-47678",
    "CVE-2024-47679",
    "CVE-2024-47684",
    "CVE-2024-47692",
    "CVE-2024-47693",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47701",
    "CVE-2024-47705",
    "CVE-2024-47707",
    "CVE-2024-47710",
    "CVE-2024-47728",
    "CVE-2024-47730",
    "CVE-2024-47737",
    "CVE-2024-47739",
    "CVE-2024-47742",
    "CVE-2024-47745",
    "CVE-2024-47749",
    "CVE-2024-49851",
    "CVE-2024-49856",
    "CVE-2024-49858",
    "CVE-2024-49861",
    "CVE-2024-49863",
    "CVE-2024-49875",
    "CVE-2024-49878",
    "CVE-2024-49881",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49884",
    "CVE-2024-49886",
    "CVE-2024-49889",
    "CVE-2024-49891",
    "CVE-2024-49899",
    "CVE-2024-49906",
    "CVE-2024-49907",
    "CVE-2024-49925",
    "CVE-2024-49927",
    "CVE-2024-49933",
    "CVE-2024-49934",
    "CVE-2024-49935",
    "CVE-2024-49940",
    "CVE-2024-49944",
    "CVE-2024-49948",
    "CVE-2024-49949",
    "CVE-2024-49952",
    "CVE-2024-49954",
    "CVE-2024-49955",
    "CVE-2024-49959",
    "CVE-2024-49960",
    "CVE-2024-49974",
    "CVE-2024-49975",
    "CVE-2024-49978",
    "CVE-2024-49983",
    "CVE-2024-49995",
    "CVE-2024-50001",
    "CVE-2024-50002",
    "CVE-2024-50006",
    "CVE-2024-50014",
    "CVE-2024-50015",
    "CVE-2024-50016",
    "CVE-2024-50024",
    "CVE-2024-50028",
    "CVE-2024-50033",
    "CVE-2024-50038",
    "CVE-2024-50039",
    "CVE-2024-50040",
    "CVE-2024-50045",
    "CVE-2024-50046",
    "CVE-2024-50047",
    "CVE-2024-50058",
    "CVE-2024-50060",
    "CVE-2024-50063",
    "CVE-2024-50067",
    "CVE-2024-50072",
    "CVE-2024-50073",
    "CVE-2024-50074",
    "CVE-2024-50082",
    "CVE-2024-50095",
    "CVE-2024-50099",
    "CVE-2024-50115",
    "CVE-2024-50131",
    "CVE-2024-50135",
    "CVE-2024-50138",
    "CVE-2024-50142",
    "CVE-2024-50143",
    "CVE-2024-50150",
    "CVE-2024-50151",
    "CVE-2024-50154",
    "CVE-2024-50167",
    "CVE-2024-50179",
    "CVE-2024-50192",
    "CVE-2024-50194",
    "CVE-2024-50195",
    "CVE-2024-50199",
    "CVE-2024-50208",
    "CVE-2024-50209",
    "CVE-2024-50241",
    "CVE-2024-50251",
    "CVE-2024-50256",
    "CVE-2024-50258",
    "CVE-2024-50262",
    "CVE-2024-50264",
    "CVE-2024-50267",
    "CVE-2024-50272",
    "CVE-2024-50278",
    "CVE-2024-50279",
    "CVE-2024-50280",
    "CVE-2024-50289",
    "CVE-2024-50296",
    "CVE-2024-50299",
    "CVE-2024-50301",
    "CVE-2024-50302",
    "CVE-2024-50304",
    "CVE-2024-53052",
    "CVE-2024-53057",
    "CVE-2024-53063",
    "CVE-2024-53066",
    "CVE-2024-53073",
    "CVE-2024-53079",
    "CVE-2024-53085",
    "CVE-2024-53088",
    "CVE-2024-53095",
    "CVE-2024-53096",
    "CVE-2024-53099",
    "CVE-2024-53104",
    "CVE-2024-53119",
    "CVE-2024-53121",
    "CVE-2024-53141",
    "CVE-2024-53142"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/26");

  script_name(english:"EulerOS 2.0 SP11 : kernel (EulerOS-SA-2025-1140)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    bonding: change ipsec_lock from spin lock to mutex(CVE-2024-46678)

    ice: protect XDP configuration with a mutex(CVE-2024-46765)

    sched/smt: Fix unbalance sched_smt_present dec/inc(CVE-2024-44958)

    mm: avoid leaving partial pfn mappings around in error case(CVE-2024-47674)

    blk_iocost: fix more out of bound shifts(CVE-2024-49933)

    x86/ioapic: Handle allocation failures gracefully(CVE-2024-49927)

    In the Linux kernel, the following vulnerability has been resolved:ntb: intel: Fix the NULL vs IS_ERR()
    bug for debugfs_create_dir()  The debugfs_create_dir() function returns error pointers. It never returns
    NULL. So use IS_ERR() to check it.(CVE-2023-52917)

    mm: call the security_mmap_file() LSM hook in remap_file_pages().(CVE-2024-47745)

    ext4: avoid use-after-free in ext4_ext_show_leaf().(CVE-2024-49889)

    tpm: Clean up TPM space after command failure(CVE-2024-49851)

    sock_map: Add a cond_resched() in sock_hash_free().(CVE-2024-47710)

    tcp: check skb is non-NULL in tcp_rto_delta_us().(CVE-2024-47684)

    ext4: avoid OOB when system.data xattr changes underneath the filesystem(CVE-2024-47701)

    ext4: fix double brelse() the buffer of the extents path(CVE-2024-49882)

    fbdev: efifb: Register sysfs groups through driver core(CVE-2024-49925)

    ext4: fix slab-use-after-free in ext4_split_extent_at().(CVE-2024-49884)

    ext4: aovid use-after-free in ext4_ext_insert_extent().(CVE-2024-49883)

    ACPI: PAD: fix crash in exit_round_robin().(CVE-2024-49935)

    ext4: update orig_path in ext4_find_extent().(CVE-2024-49881)

    padata: use integer wrap around to prevent deadlock on seq_nr overflow(CVE-2024-47739)

    drm/amd/display: Check null pointer before try to access it(CVE-2024-49906)

    netfilter: xtables: avoid NFPROTO_UNSPEC where needed(CVE-2024-50038)

    drm/amd/display: Check null pointers before using dc-clk_mgr(CVE-2024-49907)

    drivers: media: dvb-frontends/rtl2830: fix an out-of-bounds write error(CVE-2024-47697)

    uprobes: fix kernel info leak via '[uprobes]' vma(CVE-2024-49975)

    ext4: dax: fix overflowing extents beyond inode size when partially writing(CVE-2024-50015)

    net/sched: accept TCA_STAB only for root qdisc(CVE-2024-50039)

    block: fix potential invalid pointer dereference in blk_add_partition(CVE-2024-47705)

    nfsd: map the EBADMSG to nfserr_io to avoid warning(CVE-2024-49875)

    vhost/scsi: null-ptr-dereference in vhost_scsi_get_req().(CVE-2024-49863)

    thermal: core: Reference count the zone in thermal_zone_get_by_id().(CVE-2024-50028)

    bpf: Zero former ARG_PTR_TO_{LONG,INT} args in case of error(CVE-2024-47728)

    net: mdio: fix unbalanced fwnode reference count in mdio_device_release().(CVE-2022-48961)

    IB/core: Fix ib_cache_setup_one error flow cleanup(CVE-2024-47693)

    bpf: Fix helper writes to read-only maps(CVE-2024-49861)

    nfsd: return -EINVAL when namelen is 0(CVE-2024-47692)

    gpiolib: fix memory leak in gpiochip_setup_dev().(CVE-2022-48975)

    RDMA/cxgb4: Added NULL check for lookup_atid(CVE-2024-47749)

    nfsd: call cache_put if xdr_reserve_space returns NULL(CVE-2024-47737)

    igb: Do not bring the device up after non-fatal error(CVE-2024-50040)

    jbd2: stop waiting for space when jbd2_cleanup_journal_tail() returns error(CVE-2024-49959)

    crypto: hisilicon/qm - inject error before stopping queue(CVE-2024-47730)

    firmware_loader: Block path traversal(CVE-2024-47742)

    uprobe: avoid out-of-bounds memory access of fetching args(CVE-2024-50067)

    scsi: lpfc: Validate hdwq pointers before dereferencing in reset/errata paths(CVE-2024-49891)

    netfilter: br_netfilter: fix panic with metadata_dst skb(CVE-2024-50045)

    slip: make slhc_remember() more robust against malicious packets(CVE-2024-50033)

    ipv6: avoid possible NULL deref in rt6_uncached_list_flush_dev().(CVE-2024-47707)

    icmp: change the order of rate limits(CVE-2024-47678)

    serial: protect uart_port_dtr_rts() in uart_shutdown() too(CVE-2024-50058)

    NFSv4: Prevent NULL-pointer dereference in nfs42_complete_copies().(CVE-2024-50046)

    ACPI: battery: Fix possible crash when unregistering a battery hook(CVE-2024-49955)

    efistub/tpm: Use ACPI reclaim memory for event log to avoid corruption(CVE-2024-49858)

    smb: client: fix UAF in async decryption(CVE-2024-50047)

    lib/generic-radix-tree.c: Fix rare race in __genradix_ptr_alloc().(CVE-2024-47668)

    net: Fix an unsafe loop on the list(CVE-2024-50024)

    vfs: fix race between evice_inodes() and find_inode()iput().(CVE-2024-47679)

    io_uring: check if we need to reschedule during overflow flush(CVE-2024-50060)

    ext4: drop ppath from ext4_ext_replay_update_ex() to avoid double-free(CVE-2024-49983)

    ext4: fix access to uninitialised lock in fc replay path(CVE-2024-50014)

    ext4: fix timer use-after-free on failed mount(CVE-2024-49960)

    ext4: fix i_data_sem unlock order in ext4_ind_migrate().(CVE-2024-50006)

    bpf: Prevent tail call between progs attached to different hooks(CVE-2024-50063)

    NFSD: Limit the number of concurrent async COPY operations(CVE-2024-49974)

    static_call: Handle module init failure correctly in static_call_del_module().(CVE-2024-50002)

    blk-rq-qos: fix crash on rq_qos_wait vs. rq_qos_wake_function race(CVE-2024-50082)

    drm/amd/display: Initialize denominators' default to 1(CVE-2024-49899)

    drm/amd/display: Avoid overflow assignment in link_dp_cts(CVE-2024-50016)

    x86/bugs: Use code segment selector for VERW operand(CVE-2024-50072)

    parport: Proper fix for array out-of-bounds access(CVE-2024-50074)

    tipc: guard against string buffer overrun(CVE-2024-49995)

    gso: fix udp gso fraglist segmentation after pull from frag_list(CVE-2024-49978)

    drm/amd/display: Skip wbscl_set_scaler_filter if filter is null(CVE-2024-46714)

    net/mlx5: Fix error path in multi-packet WQE transmit(CVE-2024-50001)

    fs/inode: Prevent dump_mapping() accessing invalid dentry.d_name.name(CVE-2024-49934)

    resource: fix region_intersects() vs add_memory_driver_managed().(CVE-2024-49878)

    platform/x86: ISST: Fix the KASAN report slab-out-of-bounds bug(CVE-2024-49886)

    net: add more sanity checks to qdisc_pkt_len_init().(CVE-2024-49948)

    RDMA/iwcm: Fix WARNING:at_kernel/workqueue.c:#check_flush_dependency(CVE-2024-47696)

    net: avoid potential underflow in qdisc_pkt_len_init() with UFO(CVE-2024-49949)

    smb: client: fix OOBs when building SMB2_IOCTL request(CVE-2024-50151)

    l2tp: prevent possible tunnel refcount underflow(CVE-2024-49940)

    iommu/vt-d: Fix double list_add when enabling VMD in scalable mode(CVE-2022-48916)

    tty: n_gsm: Fix use-after-free in gsm_cleanup_mux(CVE-2024-50073)

    arm64: probes: Remove broken LDR (literal) uprobe support(CVE-2024-50099)

    static_call: Replace pointless WARN_ON() in static_call_module_notify().(CVE-2024-49954)

    tracing: Consider the NULL character when validating the event length(CVE-2024-50131)

    posix-clock: Fix missing timespec64 check in pc_clock_settime().(CVE-2024-50195)

    xfrm: validate new SA's prefixlen using SA family when sel.family is unset(CVE-2024-50142)

    ceph: remove the incorrect Fw reference check when dirtying pages(CVE-2024-50179)

    RDMA/mad: Improve handling of timed out WRs of mad agent(CVE-2024-50095)

    irqchip/gic-v4: Don't allow a VMOVP on a dying VPE(CVE-2024-50192)

    bpf: Use raw_spinlock_t in ringbuf(CVE-2024-50138)

    KVM: x86: Acquire kvm-srcu when handling KVM_SET_VCPU_EVENTS(CVE-2024-46830)

    x86/sgx: Fix deadlock in SGX NUMA node search(CVE-2024-49856)

    nvme-pci: fix race condition between reset and nvme_dev_disable().(CVE-2024-50135)

    NFSD: Initialize struct nfsd4_copy earlier(CVE-2024-50241)

    mm/swapfile: skip HugeTLB pages for unuse_vma(CVE-2024-50199)

    netfilter: nf_reject_ipv6: fix potential crash in nf_send_reset6().(CVE-2024-50256)

    net: hns3: fix kernel crash when uninstalling driver(CVE-2024-50296)

    sctp: set sk_state back to CLOSED if autobind fails in sctp_listen_start(CVE-2024-49944)

    net: fix crash when config small gso_max_size/gso_ipv4_max_size(CVE-2024-50258)

    bpf: Fix out-of-bounds write in trie_get_next_key().(CVE-2024-50262)

    tcp/dccp: Don't use timer_pending() in reqsk_queue_unlink().(CVE-2024-50154)

    netfilter: nft_payload: sanitize offset and length before calling skb_checksum().(CVE-2024-50251)

    be2net: fix potential memory leak in be_xmit().(CVE-2024-50167)

    bpf: support non-r10 register spill/fill to/from stack in precision tracking(CVE-2023-52920)

    udf: fix uninit-value use in udf_get_fileshortad(CVE-2024-50143)

    RDMA/bnxt_re: Add a check for memory allocation(CVE-2024-50209)

    netfilter: nf_tables: prevent nf_skb_duplicated corruption(CVE-2024-49952)

    tpm: Lock TPM chip in tpm_pm_suspend() first(CVE-2024-53085)

    io_uring/rw: fix missing NOWAIT check for O_DIRECT start write(CVE-2024-53052)

    net: missing check virtio(CVE-2024-43817)

    nfs: Fix KMSAN warning in decode_getfattr_attrs().(CVE-2024-53066)

    KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory(CVE-2024-50115)

    security/keys: fix slab-out-of-bounds in key_task_permission(CVE-2024-50301)

    RDMA/bnxt_re: Fix a bug while setting up Level-2 PBL pages(CVE-2024-50208)

    media: av7110: fix a spectre vulnerability(CVE-2024-50289)

    bpf: Check validity of link-type in bpf_link_show_fdinfo().(CVE-2024-53099)

    filemap: Fix bounds checking in filemap_read().(CVE-2024-50272)

    sctp: properly validate chunk size in sctp_sf_ootb().(CVE-2024-50299)

    arm64: probes: Fix uprobes for big-endian kernels(CVE-2024-50194)

    usb: typec: altmode should keep reference to parent(CVE-2024-50150)

    media: dvbdev: prevent the risk of out of memory access(CVE-2024-53063)

    HID: core: zero-initialize the report buffer(CVE-2024-50302)

    i40e: fix race condition by adding filter's intermediate sync state(CVE-2024-53088)

    ipv4: ip_tunnel: Fix suspicious RCU usage warning in ip_tunnel_find().(CVE-2024-50304)

    mm/thp: fix deferred split unqueue naming and locking(CVE-2024-53079)

    vsock/virtio: Initialization of the dangling pointer occurring in vsk-trans(CVE-2024-50264)

    dm cache: fix potential out-of-bounds access on the first resume(CVE-2024-50278)

    net/sched: stop qdisc_tree_reduce_backlog on TC_H_ROOT(CVE-2024-53057)

    dm cache: fix out-of-bounds access to the dirty bitset when resizing(CVE-2024-50279)

    USB: serial: io_edgeport: fix use after free in debug printk(CVE-2024-50267)

    mm: resolve faulty mmap_region() error path behaviour(CVE-2024-53096)

    media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format(CVE-2024-53104)

    dm cache: fix flushing uninitialized delayed_work on cache_ctr error(CVE-2024-50280)

    smb: client: Fix use-after-free of network namespace.(CVE-2024-53095)

    NFSD: Never decrement pending_async_copies on error(CVE-2024-53073)

    initramfs: avoid filename buffer overrun(CVE-2024-53142)

    netfilter: ipset: add missing range check in bitmap_ip_uadt(CVE-2024-53141)

    net/mlx5: fs, lock FTE when checking if active(CVE-2024-53121)

    virtio/vsock: Fix accept_queue memory leak(CVE-2024-53119)

    dmaengine: idxd: Let probe fail when workqueue cannot be enabled(CVE-2022-48868)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1140
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db865219");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53142");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-5.10.0-60.18.0.50.h1765.eulerosv2r11",
  "kernel-5.10.0-60.18.0.50.h1765.eulerosv2r11",
  "kernel-abi-stablelists-5.10.0-60.18.0.50.h1765.eulerosv2r11",
  "kernel-tools-5.10.0-60.18.0.50.h1765.eulerosv2r11",
  "kernel-tools-libs-5.10.0-60.18.0.50.h1765.eulerosv2r11",
  "python3-perf-5.10.0-60.18.0.50.h1765.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
