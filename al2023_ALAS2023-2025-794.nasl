#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2025-794.
##

include('compat.inc');

if (description)
{
  script_id(213679);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2023-45896",
    "CVE-2023-52751",
    "CVE-2024-35963",
    "CVE-2024-38632",
    "CVE-2024-46695",
    "CVE-2024-47678",
    "CVE-2024-47679",
    "CVE-2024-47682",
    "CVE-2024-47684",
    "CVE-2024-47685",
    "CVE-2024-47692",
    "CVE-2024-47693",
    "CVE-2024-47696",
    "CVE-2024-47701",
    "CVE-2024-47705",
    "CVE-2024-47706",
    "CVE-2024-47707",
    "CVE-2024-47709",
    "CVE-2024-47710",
    "CVE-2024-47728",
    "CVE-2024-47734",
    "CVE-2024-47737",
    "CVE-2024-47739",
    "CVE-2024-47742",
    "CVE-2024-47743",
    "CVE-2024-49850",
    "CVE-2024-49851",
    "CVE-2024-49855",
    "CVE-2024-49858",
    "CVE-2024-49860",
    "CVE-2024-49867",
    "CVE-2024-49868",
    "CVE-2024-49870",
    "CVE-2024-49875",
    "CVE-2024-49878",
    "CVE-2024-49881",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49884",
    "CVE-2024-49889",
    "CVE-2024-49927",
    "CVE-2024-49933",
    "CVE-2024-49935",
    "CVE-2024-49936",
    "CVE-2024-49944",
    "CVE-2024-49948",
    "CVE-2024-49949",
    "CVE-2024-49952",
    "CVE-2024-49954",
    "CVE-2024-49955",
    "CVE-2024-49957",
    "CVE-2024-49959",
    "CVE-2024-49973",
    "CVE-2024-49975",
    "CVE-2024-49978",
    "CVE-2024-49983",
    "CVE-2024-50000",
    "CVE-2024-50001",
    "CVE-2024-50002",
    "CVE-2024-50006",
    "CVE-2024-50010",
    "CVE-2024-50013",
    "CVE-2024-50015",
    "CVE-2024-50019",
    "CVE-2024-50024",
    "CVE-2024-50038",
    "CVE-2024-50039",
    "CVE-2024-50040",
    "CVE-2024-50045",
    "CVE-2024-50046",
    "CVE-2024-50048",
    "CVE-2024-50058",
    "CVE-2024-50060",
    "CVE-2024-50082",
    "CVE-2024-50083",
    "CVE-2024-50085",
    "CVE-2024-50087",
    "CVE-2024-50088",
    "CVE-2024-50095",
    "CVE-2024-50099",
    "CVE-2024-50101",
    "CVE-2024-50110",
    "CVE-2024-50115",
    "CVE-2024-50127",
    "CVE-2024-50128",
    "CVE-2024-50131",
    "CVE-2024-50136",
    "CVE-2024-50138",
    "CVE-2024-50141",
    "CVE-2024-50142",
    "CVE-2024-50143",
    "CVE-2024-50147",
    "CVE-2024-50150",
    "CVE-2024-50151",
    "CVE-2024-50153",
    "CVE-2024-50154",
    "CVE-2024-50155",
    "CVE-2024-50162",
    "CVE-2024-50163",
    "CVE-2024-50179",
    "CVE-2024-50182",
    "CVE-2024-50185",
    "CVE-2024-50186",
    "CVE-2024-50191",
    "CVE-2024-50192",
    "CVE-2024-50194",
    "CVE-2024-50195",
    "CVE-2024-50199",
    "CVE-2024-50200",
    "CVE-2024-50201"
  );

  script_name(english:"Amazon Linux 2023 : bpftool, kernel, kernel-devel (ALAS2023-2025-794)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2025-794 advisory.

    ntfs3 in the Linux kernel through 6.8.0 allows a physically proximate attacker to read kernel memory by
    mounting a filesystem (e.g., if a Linux distribution is configured to allow unprivileged mounts of
    removable media) and then leveraging local access to trigger an out-of-bounds read. A length value can be
    larger than the amount of memory allocated. NOTE: the supplier's perspective is that there is no
    vulnerability when an attack requires an attacker-modified filesystem image. (CVE-2023-45896)

    In the Linux kernel, the following vulnerability has been resolved:

    smb: client: fix use-after-free in smb2_query_info_compound() (CVE-2023-52751)

    In the Linux kernel, the following vulnerability has been resolved:

    Bluetooth: hci_sock: Fix not validating setsockopt user input (CVE-2024-35963)

    In the Linux kernel, the following vulnerability has been resolved:

    vfio/pci: fix potential memory leak in vfio_intx_enable() (CVE-2024-38632)

    In the Linux kernel, the following vulnerability has been resolved:

    selinux,smack: don't bypass permissions check in inode_setsecctx hook (CVE-2024-46695)

    In the Linux kernel, the following vulnerability has been resolved:

    icmp: change the order of rate limits (CVE-2024-47678)

    In the Linux kernel, the following vulnerability has been resolved:

    vfs: fix race between evice_inodes() and find_inode()&iput() (CVE-2024-47679)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: sd: Fix off-by-one error in sd_read_block_characteristics() (CVE-2024-47682)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: check skb is non-NULL in tcp_rto_delta_us() (CVE-2024-47684)

    syzbot reported that nf_reject_ip6_tcphdr_put() was possibly sending garbage on the four reserved tcp bits
    (th->res1)

    Use skb_put_zero() to clear the whole TCP header, as done in nf_reject_ip_tcphdr_put() (CVE-2024-47685)

    In the Linux kernel, the following vulnerability has been resolved:

    nfsd: return -EINVAL when namelen is 0 (CVE-2024-47692)

    In the Linux kernel, the following vulnerability has been resolved:

    IB/core: Fix ib_cache_setup_one error flow cleanup (CVE-2024-47693)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/iwcm: Fix WARNING:at_kernel/workqueue.c:#check_flush_dependency (CVE-2024-47696)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: avoid OOB when system.data xattr changes underneath the filesystem (CVE-2024-47701)

    In the Linux kernel, the following vulnerability has been resolved:

    block: fix potential invalid pointer dereference in blk_add_partition (CVE-2024-47705)

    In the Linux kernel, the following vulnerability has been resolved:

    block, bfq: fix possible UAF for bfqq->bic with merge chain (CVE-2024-47706)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: avoid possible NULL deref in rt6_uncached_list_flush_dev() (CVE-2024-47707)

    In the Linux kernel, the following vulnerability has been resolved:

    can: bcm: Clear bo->bcm_proc_read after remove_proc_entry(). (CVE-2024-47709)

    In the Linux kernel, the following vulnerability has been resolved:

    sock_map: Add a cond_resched() in sock_hash_free() (CVE-2024-47710)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Zero former ARG_PTR_TO_{LONG,INT} args in case of error (CVE-2024-47728)

    In the Linux kernel, the following vulnerability has been resolved:

    bonding: Fix unnecessary warnings and logs from bond_xdp_get_xmit_slave() (CVE-2024-47734)

    In the Linux kernel, the following vulnerability has been resolved:

    nfsd: call cache_put if xdr_reserve_space returns NULL (CVE-2024-47737)

    In the Linux kernel, the following vulnerability has been resolved:

    padata: use integer wrap around to prevent deadlock on seq_nr overflow (CVE-2024-47739)

    In the Linux kernel, the following vulnerability has been resolved:

    firmware_loader: Block path traversal (CVE-2024-47742)

    In the Linux kernel, the following vulnerability has been resolved:

    KEYS: prevent NULL pointer dereference in find_asymmetric_key() (CVE-2024-47743)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: correctly handle malformed BPF_CORE_TYPE_ID_LOCAL relos (CVE-2024-49850)

    In the Linux kernel, the following vulnerability has been resolved:

    tpm: Clean up TPM space after command failure (CVE-2024-49851)

    In the Linux kernel, the following vulnerability has been resolved:

    nbd: fix race between timeout and normal completion (CVE-2024-49855)

    In the Linux kernel, the following vulnerability has been resolved:

    efistub/tpm: Use ACPI reclaim memory for event log to avoid corruption (CVE-2024-49858)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: sysfs: validate return type of _STR method (CVE-2024-49860)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: wait for fixup workers before stopping cleaner kthread during umount (CVE-2024-49867)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: fix a NULL pointer dereference when failed to start a new trasacntion (CVE-2024-49868)

    In the Linux kernel, the following vulnerability has been resolved:

    cachefiles: fix dentry leak in cachefiles_open_file() (CVE-2024-49870)

    In the Linux kernel, the following vulnerability has been resolved:

    nfsd: map the EBADMSG to nfserr_io to avoid warning (CVE-2024-49875)

    In the Linux kernel, the following vulnerability has been resolved:

    resource: fix region_intersects() vs add_memory_driver_managed() (CVE-2024-49878)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: update orig_path in ext4_find_extent() (CVE-2024-49881)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix double brelse() the buffer of the extents path (CVE-2024-49882)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: aovid use-after-free in ext4_ext_insert_extent() (CVE-2024-49883)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix slab-use-after-free in ext4_split_extent_at() (CVE-2024-49884)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: avoid use-after-free in ext4_ext_show_leaf() (CVE-2024-49889)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/ioapic: Handle allocation failures gracefully (CVE-2024-49927)

    In the Linux kernel, the following vulnerability has been resolved:

    blk_iocost: fix more out of bound shifts (CVE-2024-49933)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: PAD: fix crash in exit_round_robin() (CVE-2024-49935)

    In the Linux kernel, the following vulnerability has been resolved:

    net/xen-netback: prevent UAF in xenvif_flush_hash() (CVE-2024-49936)

    In the Linux kernel, the following vulnerability has been resolved:

    sctp: set sk_state back to CLOSED if autobind fails in sctp_listen_start (CVE-2024-49944)

    In the Linux kernel, the following vulnerability has been resolved:

    net: add more sanity checks to qdisc_pkt_len_init() (CVE-2024-49948)

    In the Linux kernel, the following vulnerability has been resolved:

    net: avoid potential underflow in qdisc_pkt_len_init() with UFO (CVE-2024-49949)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_tables: prevent nf_skb_duplicated corruption (CVE-2024-49952)

    In the Linux kernel, the following vulnerability has been resolved:

    static_call: Replace pointless WARN_ON() in static_call_module_notify() (CVE-2024-49954)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: battery: Fix possible crash when unregistering a battery hook (CVE-2024-49955)

    In the Linux kernel, the following vulnerability has been resolved:

    ocfs2: fix null-ptr-deref when journal load failed. (CVE-2024-49957)

    In the Linux kernel, the following vulnerability has been resolved:

    jbd2: stop waiting for space when jbd2_cleanup_journal_tail() returns error (CVE-2024-49959)

    In the Linux kernel, the following vulnerability has been resolved:

    r8169: add tally counter fields added with RTL8125 (CVE-2024-49973)

    In the Linux kernel, the following vulnerability has been resolved:

    uprobes: fix kernel info leak via [uprobes] vma (CVE-2024-49975)

    In the Linux kernel, the following vulnerability has been resolved:

    gso: fix udp gso fraglist segmentation after pull from frag_list (CVE-2024-49978)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: drop ppath from ext4_ext_replay_update_ex() to avoid double-free (CVE-2024-49983)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5e: Fix NULL deref in mlx5e_tir_builder_alloc() (CVE-2024-50000)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5: Fix error path in multi-packet WQE transmit (CVE-2024-50001)

    In the Linux kernel, the following vulnerability has been resolved:

    static_call: Handle module init failure correctly in static_call_del_module() (CVE-2024-50002)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix i_data_sem unlock order in ext4_ind_migrate() (CVE-2024-50006)

    In the Linux kernel, the following vulnerability has been resolved:

    exec: don't WARN for racy path_noexec check (CVE-2024-50010)

    In the Linux kernel, the following vulnerability has been resolved:

    exfat: fix memory leak in exfat_load_bitmap() (CVE-2024-50013)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: dax: fix overflowing extents beyond inode size when partially writing (CVE-2024-50015)

    In the Linux kernel, the following vulnerability has been resolved:

    kthread: unpark only parked kthread (CVE-2024-50019)

    In the Linux kernel, the following vulnerability has been resolved:

    net: Fix an unsafe loop on the list (CVE-2024-50024)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: xtables: avoid NFPROTO_UNSPEC where needed (CVE-2024-50038)

    In the Linux kernel, the following vulnerability has been resolved:

    net/sched: accept TCA_STAB only for root qdisc (CVE-2024-50039)

    In the Linux kernel, the following vulnerability has been resolved:

    igb: Do not bring the device up after non-fatal error (CVE-2024-50040)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: br_netfilter: fix panic with metadata_dst skb (CVE-2024-50045)

    In the Linux kernel, the following vulnerability has been resolved:

    NFSv4: Prevent NULL-pointer dereference in nfs42_complete_copies() (CVE-2024-50046)

    In the Linux kernel, the following vulnerability has been resolved:

    fbcon: Fix a NULL pointer dereference issue in fbcon_putcs (CVE-2024-50048)

    In the Linux kernel, the following vulnerability has been resolved:

    serial: protect uart_port_dtr_rts() in uart_shutdown() too (CVE-2024-50058)

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring: check if we need to reschedule during overflow flush (CVE-2024-50060)

    In the Linux kernel, the following vulnerability has been resolved:

    blk-rq-qos: fix crash on rq_qos_wait vs. rq_qos_wake_function race (CVE-2024-50082)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: fix mptcp DSS corruption due to large pmtu xmit (CVE-2024-50083)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: pm: fix UaF read in mptcp_pm_nl_rm_addr_or_subflow (CVE-2024-50085)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: fix uninitialized pointer free on read_alloc_one_name() error (CVE-2024-50087)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: fix uninitialized pointer free in add_inode_ref() (CVE-2024-50088)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/mad: Improve handling of timed out WRs of mad agent (CVE-2024-50095)

    In the Linux kernel, the following vulnerability has been resolved:

    arm64: probes: Remove broken LDR (literal) uprobe support (CVE-2024-50099)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu/vt-d: Fix incorrect pci_for_each_dma_alias() for non-PCI devices (CVE-2024-50101)

    In the Linux kernel, the following vulnerability has been resolved:

    xfrm: fix one more kernel-infoleak in algo dumping (CVE-2024-50110)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory (CVE-2024-50115)

    In the Linux kernel, the following vulnerability has been resolved:

    net: sched: fix use-after-free in taprio_change() (CVE-2024-50127)

    In the Linux kernel, the following vulnerability has been resolved:

    net: wwan: fix global oob in wwan_rtnl_policy (CVE-2024-50128)

    In the Linux kernel, the following vulnerability has been resolved:

    tracing: Consider the NULL character when validating the event length (CVE-2024-50131)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5: Unregister notifier on eswitch init failure (CVE-2024-50136)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Use raw_spinlock_t in ringbuf (CVE-2024-50138)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: PRM: Find EFI_MEMORY_RUNTIME block for PRM handler and context (CVE-2024-50141)

    In the Linux kernel, the following vulnerability has been resolved:

    xfrm: validate new SA's prefixlen using SA family when sel.family is unset (CVE-2024-50142)

    In the Linux kernel, the following vulnerability has been resolved:

    udf: fix uninit-value use in udf_get_fileshortad (CVE-2024-50143)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5: Fix command bitmask initialization (CVE-2024-50147)

    In the Linux kernel, the following vulnerability has been resolved:

    usb: typec: altmode should keep reference to parent (CVE-2024-50150)

    In the Linux kernel, the following vulnerability has been resolved:

    smb: client: fix OOBs when building SMB2_IOCTL request (CVE-2024-50151)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: target: core: Fix null-ptr-deref in target_alloc_device() (CVE-2024-50153)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp/dccp: Don't use timer_pending() in reqsk_queue_unlink(). (CVE-2024-50154)

    In the Linux kernel, the following vulnerability has been resolved:

    netdevsim: use cond_resched() in nsim_dev_trap_report_work() (CVE-2024-50155)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: devmap: provide rxq after redirect (CVE-2024-50162)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Make sure internal and UAPI bpf_redirect flags don't overlap (CVE-2024-50163)

    In the Linux kernel, the following vulnerability has been resolved:

    ceph: remove the incorrect Fw reference check when dirtying pages (CVE-2024-50179)

    In the Linux kernel, the following vulnerability has been resolved:

    secretmem: disable memfd_secret() if arch cannot set direct map (CVE-2024-50182)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: handle consistently DSS corruption (CVE-2024-50185)

    In the Linux kernel, the following vulnerability has been resolved:

    net: explicitly clear the sk pointer, when pf->create fails (CVE-2024-50186)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: don't set SB_RDONLY after filesystem errors (CVE-2024-50191)

    In the Linux kernel, the following vulnerability has been resolved:

    irqchip/gic-v4: Don't allow a VMOVP on a dying VPE (CVE-2024-50192)

    In the Linux kernel, the following vulnerability has been resolved:

    arm64: probes: Fix uprobes for big-endian kernels (CVE-2024-50194)

    In the Linux kernel, the following vulnerability has been resolved:

    posix-clock: Fix missing timespec64 check in pc_clock_settime() (CVE-2024-50195)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/swapfile: skip HugeTLB pages for unuse_vma (CVE-2024-50199)

    In the Linux kernel, the following vulnerability has been resolved:

    maple_tree: correct tree corruption on spanning store (CVE-2024-50200)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/radeon: Fix encoder->possible_clones (CVE-2024-50201)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2025-794.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-45896.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52751.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35963.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-38632.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-46695.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47678.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47679.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47682.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47684.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47685.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47692.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47693.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47696.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47701.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47705.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47706.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47707.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47709.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47710.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47728.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47734.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47737.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47739.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47742.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47743.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49850.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49851.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49855.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49858.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49860.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49867.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49868.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49870.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49875.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49878.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49881.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49882.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49883.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49884.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49889.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49927.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49933.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49935.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49936.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49944.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49948.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49949.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49952.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49954.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49955.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49957.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49959.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49973.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49975.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49978.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49983.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50000.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50001.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50002.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50006.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50010.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50013.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50015.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50019.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50024.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50038.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50039.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50040.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50045.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50046.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50048.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50058.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50060.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50082.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50083.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50085.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50087.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50088.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50095.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50099.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50101.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50110.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50115.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50127.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50128.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50131.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50136.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50138.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50141.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50142.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50143.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50147.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50150.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50151.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50153.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50154.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50155.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50162.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50163.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50179.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50182.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50185.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50186.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50191.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50192.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50194.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50195.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50199.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50200.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50201.html");
  script_set_attribute(attribute:"solution", value:
"");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-libbpf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-libbpf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-libbpf-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-6.1.115-126.197");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-modules-extra-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "kpatch.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");
include("hotfixes.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2023-45896", "CVE-2023-52751", "CVE-2024-35963", "CVE-2024-38632", "CVE-2024-46695", "CVE-2024-47678", "CVE-2024-47679", "CVE-2024-47682", "CVE-2024-47684", "CVE-2024-47685", "CVE-2024-47692", "CVE-2024-47693", "CVE-2024-47696", "CVE-2024-47701", "CVE-2024-47705", "CVE-2024-47706", "CVE-2024-47707", "CVE-2024-47709", "CVE-2024-47710", "CVE-2024-47728", "CVE-2024-47734", "CVE-2024-47737", "CVE-2024-47739", "CVE-2024-47742", "CVE-2024-47743", "CVE-2024-49850", "CVE-2024-49851", "CVE-2024-49855", "CVE-2024-49858", "CVE-2024-49860", "CVE-2024-49867", "CVE-2024-49868", "CVE-2024-49870", "CVE-2024-49875", "CVE-2024-49878", "CVE-2024-49881", "CVE-2024-49882", "CVE-2024-49883", "CVE-2024-49884", "CVE-2024-49889", "CVE-2024-49927", "CVE-2024-49933", "CVE-2024-49935", "CVE-2024-49936", "CVE-2024-49944", "CVE-2024-49948", "CVE-2024-49949", "CVE-2024-49952", "CVE-2024-49954", "CVE-2024-49955", "CVE-2024-49957", "CVE-2024-49959", "CVE-2024-49973", "CVE-2024-49975", "CVE-2024-49978", "CVE-2024-49983", "CVE-2024-50000", "CVE-2024-50001", "CVE-2024-50002", "CVE-2024-50006", "CVE-2024-50010", "CVE-2024-50013", "CVE-2024-50015", "CVE-2024-50019", "CVE-2024-50024", "CVE-2024-50038", "CVE-2024-50039", "CVE-2024-50040", "CVE-2024-50045", "CVE-2024-50046", "CVE-2024-50048", "CVE-2024-50058", "CVE-2024-50060", "CVE-2024-50082", "CVE-2024-50083", "CVE-2024-50085", "CVE-2024-50087", "CVE-2024-50088", "CVE-2024-50095", "CVE-2024-50099", "CVE-2024-50101", "CVE-2024-50110", "CVE-2024-50115", "CVE-2024-50127", "CVE-2024-50128", "CVE-2024-50131", "CVE-2024-50136", "CVE-2024-50138", "CVE-2024-50141", "CVE-2024-50142", "CVE-2024-50143", "CVE-2024-50147", "CVE-2024-50150", "CVE-2024-50151", "CVE-2024-50153", "CVE-2024-50154", "CVE-2024-50155", "CVE-2024-50162", "CVE-2024-50163", "CVE-2024-50179", "CVE-2024-50182", "CVE-2024-50185", "CVE-2024-50186", "CVE-2024-50191", "CVE-2024-50192", "CVE-2024-50194", "CVE-2024-50195", "CVE-2024-50199", "CVE-2024-50200", "CVE-2024-50201");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS2023-2025-794");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var pkgs = [
    {'reference':'bpftool-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-aarch64-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.115-126.197-1.0-0.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.115-126.197-1.0-0.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.115-126.197.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.115-126.197.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / etc");
}
