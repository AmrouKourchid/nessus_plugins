#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-696.
##

include('compat.inc');

if (description)
{
  script_id(205093);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id(
    "CVE-2023-52656",
    "CVE-2024-23307",
    "CVE-2024-25742",
    "CVE-2024-26584",
    "CVE-2024-26585",
    "CVE-2024-26642",
    "CVE-2024-26643",
    "CVE-2024-26809",
    "CVE-2024-26810",
    "CVE-2024-26812",
    "CVE-2024-26815",
    "CVE-2024-26816",
    "CVE-2024-26860",
    "CVE-2024-26861",
    "CVE-2024-26862",
    "CVE-2024-26863",
    "CVE-2024-26864",
    "CVE-2024-26865",
    "CVE-2024-26868",
    "CVE-2024-26870",
    "CVE-2024-26878",
    "CVE-2024-26880",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26891",
    "CVE-2024-26894",
    "CVE-2024-26898",
    "CVE-2024-26901",
    "CVE-2024-26906",
    "CVE-2024-26933",
    "CVE-2024-26934",
    "CVE-2024-26935",
    "CVE-2024-26937",
    "CVE-2024-26938",
    "CVE-2024-26946",
    "CVE-2024-26950",
    "CVE-2024-26951",
    "CVE-2024-26958",
    "CVE-2024-26960",
    "CVE-2024-26964",
    "CVE-2024-26973",
    "CVE-2024-26976",
    "CVE-2024-26977",
    "CVE-2024-27025",
    "CVE-2024-27038",
    "CVE-2024-27047",
    "CVE-2024-27065",
    "CVE-2024-27388",
    "CVE-2024-27389",
    "CVE-2024-27390",
    "CVE-2024-27435",
    "CVE-2024-27437",
    "CVE-2024-35791",
    "CVE-2024-35800",
    "CVE-2024-35801",
    "CVE-2024-35804",
    "CVE-2024-35805",
    "CVE-2024-35809",
    "CVE-2024-35815",
    "CVE-2024-35823",
    "CVE-2024-35826",
    "CVE-2024-35827",
    "CVE-2024-36031"
  );

  script_name(english:"Amazon Linux 2023 : bpftool, kernel, kernel-devel (ALAS2023-2024-696)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2024-696 advisory.

    2024-12-05: CVE-2024-26973 was added to this advisory.

    2024-12-05: CVE-2024-26934 was added to this advisory.

    2024-12-05: CVE-2024-26891 was added to this advisory.

    2024-12-05: CVE-2024-26882 was added to this advisory.

    2024-12-05: CVE-2024-26894 was added to this advisory.

    2024-12-05: CVE-2024-26906 was added to this advisory.

    2024-12-05: CVE-2024-27435 was added to this advisory.

    2024-12-05: CVE-2024-35791 was added to this advisory.

    2024-12-05: CVE-2024-27047 was added to this advisory.

    2024-12-05: CVE-2024-26937 was added to this advisory.

    2024-12-05: CVE-2024-26870 was added to this advisory.

    2024-12-05: CVE-2024-26864 was added to this advisory.

    2024-12-05: CVE-2024-26860 was added to this advisory.

    2024-09-12: CVE-2024-35827 was added to this advisory.

    2024-09-12: CVE-2024-35823 was added to this advisory.

    2024-09-12: CVE-2024-35800 was added to this advisory.

    2024-09-12: CVE-2024-35804 was added to this advisory.

    2024-09-12: CVE-2024-35815 was added to this advisory.

    2024-09-12: CVE-2024-35826 was added to this advisory.

    2024-08-14: CVE-2024-23307 was added to this advisory.

    2024-08-14: CVE-2024-25742 was added to this advisory.

    2024-08-14: CVE-2024-26865 was added to this advisory.

    2024-08-14: CVE-2024-26862 was added to this advisory.

    2024-08-14: CVE-2024-26585 was added to this advisory.

    2024-08-14: CVE-2024-26815 was added to this advisory.

    2024-08-14: CVE-2024-35805 was added to this advisory.

    2024-08-14: CVE-2024-26863 was added to this advisory.

    2024-08-14: CVE-2024-26643 was added to this advisory.

    2024-08-14: CVE-2024-26878 was added to this advisory.

    2024-08-14: CVE-2024-26812 was added to this advisory.

    2024-08-14: CVE-2024-26584 was added to this advisory.

    2024-08-14: CVE-2024-27388 was added to this advisory.

    2024-08-14: CVE-2024-26642 was added to this advisory.

    2024-08-14: CVE-2024-36031 was added to this advisory.

    2024-08-14: CVE-2024-35801 was added to this advisory.

    2024-08-14: CVE-2024-26880 was added to this advisory.

    2024-08-14: CVE-2024-26810 was added to this advisory.

    2024-08-14: CVE-2024-27038 was added to this advisory.

    2024-08-14: CVE-2023-52656 was added to this advisory.

    2024-08-14: CVE-2024-26898 was added to this advisory.

    2024-08-14: CVE-2024-26861 was added to this advisory.

    2024-08-14: CVE-2024-35809 was added to this advisory.

    2024-08-14: CVE-2024-27437 was added to this advisory.

    2024-08-14: CVE-2024-26809 was added to this advisory.

    2024-08-14: CVE-2024-26883 was added to this advisory.

    2024-08-14: CVE-2024-26901 was added to this advisory.

    2024-08-14: CVE-2024-26816 was added to this advisory.

    2024-08-14: CVE-2024-26868 was added to this advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring: drop any code related to SCM_RIGHTS (CVE-2023-52656)

    Integer Overflow or Wraparound vulnerability in Linux kernel on x86 and ARM (md, raid, raid5 modules)
    allows Forced Integer Overflow. (CVE-2024-23307)

    A malicious hypervisor can potentially break confidentiality and integrity of Linux SEV-SNP guests by
    injecting interrupts. (CVE-2024-25742)

    In the Linux kernel, the following vulnerability has been resolved:

    net: tls: handle backlogging of crypto requests

    Since we're setting the CRYPTO_TFM_REQ_MAY_BACKLOG flag on ourrequests to the crypto API,
    crypto_aead_{encrypt,decrypt} can return-EBUSY instead of -EINPROGRESS in valid situations. For example,
    whenthe cryptd queue for AESNI is full (easy to trigger with anartificially low
    cryptd.cryptd_max_cpu_qlen), requests will be enqueuedto the backlog but still processed. In that case,
    the async callbackwill also be called twice: first with err == -EINPROGRESS, which itseems we can just
    ignore, then with err == 0.

    Compared to Sabrina's original patch this version uses the newtls_*crypt_async_wait() helpers and converts
    the EBUSY toEINPROGRESS to avoid having to modify all the error handlingpaths. The handling is identical.
    (CVE-2024-26584)

    In the Linux kernel, the following vulnerability has been resolved:

    tls: fix race between tx work scheduling and socket close

    Similarly to previous commit, the submitting thread (recvmsg/sendmsg)may exit as soon as the async crypto
    handler calls complete().Reorder scheduling the work before calling complete().This seems more logical in
    the first place, as it'sthe inverse order of what the submitting thread will do. (CVE-2024-26585)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_tables: disallow anonymous set with timeout flag (CVE-2024-26642)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_tables: mark set as dead when unbinding anonymous set with timeout (CVE-2024-26643)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_set_pipapo: release elements in clone only from destroy path (CVE-2024-26809)

    In the Linux kernel, the following vulnerability has been resolved:

    vfio/pci: Lock external INTx masking ops (CVE-2024-26810)

    In the Linux kernel, the following vulnerability has been resolved:

    vfio/pci: Create persistent INTx handler (CVE-2024-26812)

    In the Linux kernel, the following vulnerability has been resolved:

    net/sched: taprio: proper TCA_TAPRIO_TC_ENTRY_INDEX check (CVE-2024-26815)

    In the Linux kernel, the following vulnerability has been resolved:

    x86, relocs: Ignore relocations in .notes section (CVE-2024-26816)

    In the Linux kernel, the following vulnerability has been resolved:

    dm-integrity: fix a memory leak when rechecking the data (CVE-2024-26860)

    In the Linux kernel, the following vulnerability has been resolved:

    wireguard: receive: annotate data-race around receiving_counter.counter (CVE-2024-26861)

    In the Linux kernel, the following vulnerability has been resolved:

    packet: annotate data-races around ignore_outgoing (CVE-2024-26862)

    In the Linux kernel, the following vulnerability has been resolved:

    hsr: Fix uninit-value access in hsr_get_node() (CVE-2024-26863)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: Fix refcnt handling in __inet_hash_connect(). (CVE-2024-26864)

    In the Linux kernel, the following vulnerability has been resolved: rds: tcp: Fix use-after-free of net in
    reqsk_timer_handler(). syzkaller reported a warning of netns tracker [0] followed by KASAN splat [1] and
    another ref tracker warning [1]. syzkaller could not find a repro, but in the log, the only suspicious
    sequence was as follows: 18:26:22 executing program 1: r0 = socket$inet6_mptcp(0xa, 0x1, 0x106) ...
    connect$inet6(r0, &(0x7f0000000080)={0xa, 0x4001, 0x0, @loopback}, 0x1c) (async) The notable thing here is
    0x4001 in connect(), which is RDS_TCP_PORT. (CVE-2024-26865)

    In the Linux kernel, the following vulnerability has been resolved:

    nfs: fix panic when nfs4_ff_layout_prepare_ds() fails (CVE-2024-26868)

    In the Linux kernel, the following vulnerability has been resolved:

    NFSv4.2: fix nfs4_listxattr kernel BUG at mm/usercopy.c:102 (CVE-2024-26870)

    In the Linux kernel, the following vulnerability has been resolved:

    quota: Fix potential NULL pointer dereference (CVE-2024-26878)

    In the Linux kernel, the following vulnerability has been resolved:

    dm: call the resume method on internal suspend (CVE-2024-26880)

    In the Linux kernel, the following vulnerability has been resolved:

    net: ip_tunnel: make sure to pull inner header in ip_tunnel_rcv() (CVE-2024-26882)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Fix stackmap overflow check on 32-bit arches (CVE-2024-26883)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu/vt-d: Don't issue ATS Invalidation request when device is disconnected (CVE-2024-26891)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: processor_idle: Fix memory leak in acpi_processor_power_exit() (CVE-2024-26894)

    In the Linux kernel, the following vulnerability has been resolved:

    aoe: fix the potential use-after-free problem in aoecmd_cfg_pkts (CVE-2024-26898)

    In the Linux kernel, the following vulnerability has been resolved:

    do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak (CVE-2024-26901)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/mm: Disallow vsyscall page read for copy_from_kernel_nofault() (CVE-2024-26906)

    In the Linux kernel, the following vulnerability has been resolved:

    USB: core: Fix deadlock in port disable sysfs attribute (CVE-2024-26933)

    In the Linux kernel, the following vulnerability has been resolved:

    USB: core: Fix deadlock in usb_deauthorize_interface() (CVE-2024-26934)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: core: Fix unremoved procfs host directory regression (CVE-2024-26935)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/i915/gt: Reset queue_priority_hint on parking (CVE-2024-26937)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/i915/bios: Tolerate devdata==NULL in intel_bios_encoder_supports_dp_dual_mode() (CVE-2024-26938)

    In the Linux kernel, the following vulnerability has been resolved:

    kprobes/x86: Use copy_from_kernel_nofault() to read from unsafe address (CVE-2024-26946)

    In the Linux kernel, the following vulnerability has been resolved:

    wireguard: netlink: access device through ctx instead of peer (CVE-2024-26950)

    In the Linux kernel, the following vulnerability has been resolved:

    wireguard: netlink: check for dangling peer via is_dead instead of empty list (CVE-2024-26951)

    In the Linux kernel, the following vulnerability has been resolved:

    nfs: fix UAF in direct writes (CVE-2024-26958)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: swap: fix race between free_swap_and_cache() and swapoff() (CVE-2024-26960)

    In the Linux kernel, the following vulnerability has been resolved:

    usb: xhci: Add error handling in xhci_map_urb_for_dma (CVE-2024-26964)

    In the Linux kernel, the following vulnerability has been resolved:

    fat: fix uninitialized field in nostale filehandles (CVE-2024-26973)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: Always flush async #PF workqueue when vCPU is being destroyed (CVE-2024-26976)

    In the Linux kernel, the following vulnerability has been resolved:

    pci_iounmap(): Fix MMIO mapping leak (CVE-2024-26977)

    In the Linux kernel, the following vulnerability has been resolved:

    nbd: null check for nla_nest_start (CVE-2024-27025)

    In the Linux kernel, the following vulnerability has been resolved:

    clk: Fix clk_core_get NULL dereference (CVE-2024-27038)

    In the Linux kernel, the following vulnerability has been resolved:

    net: phy: fix phy_get_internal_delay accessing an empty array (CVE-2024-27047)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_tables: do not compare internal table flags on updates (CVE-2024-27065)

    In the Linux kernel, the following vulnerability has been resolved:

    SUNRPC: fix some memleaks in gssx_dec_option_array (CVE-2024-27388)

    In the Linux kernel, the following vulnerability has been resolved:

    pstore: inode: Only d_invalidate() is needed (CVE-2024-27389)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: mcast: remove one synchronize_net() barrier in ipv6_mc_down() (CVE-2024-27390)

    In the Linux kernel, the following vulnerability has been resolved:

    nvme: fix reconnection fail due to reserved tag allocation (CVE-2024-27435)

    In the Linux kernel, the following vulnerability has been resolved:

    vfio/pci: Disable auto-enable of exclusive INTx IRQ (CVE-2024-27437)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: SVM: Flush pages under kvm->lock to fix UAF in svm_register_enc_region() (CVE-2024-35791)

    In the Linux kernel, the following vulnerability has been resolved:

    efi: fix panic in kdump kernel (CVE-2024-35800)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/fpu: Keep xfd_state in sync with MSR_IA32_XFD (CVE-2024-35801)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: x86: Mark target gfn of emulated atomic instruction as dirty (CVE-2024-35804)

    In the Linux kernel, the following vulnerability has been resolved:

    dm snapshot: fix lockup in dm_exception_table_exit (CVE-2024-35805)

    In the Linux kernel, the following vulnerability has been resolved:

    PCI/PM: Drain runtime-idle callbacks before driver removal (CVE-2024-35809)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/aio: Check IOCB_AIO_RW before the struct aio_kiocb conversion (CVE-2024-35815)

    In the Linux kernel, the following vulnerability has been resolved:

    vt: fix unicode buffer corruption when deleting characters (CVE-2024-35823)

    In the Linux kernel, the following vulnerability has been resolved:

    block: Fix page refcounts for unaligned buffers in __bio_release_pages() (CVE-2024-35826)

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring/net: fix overflow check in io_recvmsg_mshot_prep() (CVE-2024-35827)

    In the Linux kernel, the following vulnerability has been resolved:

    keys: Fix overwrite of key expiration on instantiation (CVE-2024-36031)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-696.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52656.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-23307.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-25742.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26584.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26585.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26642.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26643.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26809.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26810.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26812.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26815.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26816.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26860.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26861.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26862.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26863.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26864.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26865.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26868.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26870.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26878.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26880.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26882.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26883.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26891.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26894.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26898.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26901.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26906.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26933.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26934.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26935.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26937.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26938.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26946.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26950.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26951.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26958.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26960.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26964.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26973.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26976.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26977.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27025.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27038.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27047.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27065.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27388.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27389.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27390.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27435.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27437.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35791.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35800.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35801.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35804.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35805.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35809.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35815.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35823.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35826.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35827.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36031.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update kernel --releasever 2023.5.20240805' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26958");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/06");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-6.1.84-99.169");
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

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list("CVE-2023-52656", "CVE-2024-23307", "CVE-2024-25742", "CVE-2024-26584", "CVE-2024-26585", "CVE-2024-26642", "CVE-2024-26643", "CVE-2024-26809", "CVE-2024-26810", "CVE-2024-26812", "CVE-2024-26815", "CVE-2024-26816", "CVE-2024-26860", "CVE-2024-26861", "CVE-2024-26862", "CVE-2024-26863", "CVE-2024-26864", "CVE-2024-26865", "CVE-2024-26868", "CVE-2024-26870", "CVE-2024-26878", "CVE-2024-26880", "CVE-2024-26882", "CVE-2024-26883", "CVE-2024-26891", "CVE-2024-26894", "CVE-2024-26898", "CVE-2024-26901", "CVE-2024-26906", "CVE-2024-26933", "CVE-2024-26934", "CVE-2024-26935", "CVE-2024-26937", "CVE-2024-26938", "CVE-2024-26946", "CVE-2024-26950", "CVE-2024-26951", "CVE-2024-26958", "CVE-2024-26960", "CVE-2024-26964", "CVE-2024-26973", "CVE-2024-26976", "CVE-2024-26977", "CVE-2024-27025", "CVE-2024-27038", "CVE-2024-27047", "CVE-2024-27065", "CVE-2024-27388", "CVE-2024-27389", "CVE-2024-27390", "CVE-2024-27435", "CVE-2024-27437", "CVE-2024-35791", "CVE-2024-35800", "CVE-2024-35801", "CVE-2024-35804", "CVE-2024-35805", "CVE-2024-35809", "CVE-2024-35815", "CVE-2024-35823", "CVE-2024-35826", "CVE-2024-35827", "CVE-2024-36031");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS2023-2024-696");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var pkgs = [
    {'reference':'bpftool-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-aarch64-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.84-99.169-1.0-0.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.84-99.169-1.0-0.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.84-99.169.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.84-99.169.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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
