#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207120);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_cve_id(
    "CVE-2021-46952",
    "CVE-2021-47222",
    "CVE-2021-47223",
    "CVE-2021-47230",
    "CVE-2021-47236",
    "CVE-2021-47238",
    "CVE-2021-47245",
    "CVE-2021-47248",
    "CVE-2021-47250",
    "CVE-2021-47255",
    "CVE-2021-47259",
    "CVE-2021-47261",
    "CVE-2021-47265",
    "CVE-2021-47276",
    "CVE-2021-47277",
    "CVE-2021-47280",
    "CVE-2021-47284",
    "CVE-2021-47288",
    "CVE-2021-47293",
    "CVE-2021-47301",
    "CVE-2021-47302",
    "CVE-2021-47308",
    "CVE-2021-47319",
    "CVE-2021-47328",
    "CVE-2021-47329",
    "CVE-2021-47341",
    "CVE-2021-47342",
    "CVE-2021-47353",
    "CVE-2021-47376",
    "CVE-2021-47395",
    "CVE-2021-47397",
    "CVE-2021-47399",
    "CVE-2021-47405",
    "CVE-2021-47407",
    "CVE-2021-47416",
    "CVE-2021-47418",
    "CVE-2021-47424",
    "CVE-2021-47425",
    "CVE-2021-47427",
    "CVE-2021-47434",
    "CVE-2021-47438",
    "CVE-2021-47456",
    "CVE-2021-47464",
    "CVE-2021-47466",
    "CVE-2021-47468",
    "CVE-2021-47473",
    "CVE-2021-47478",
    "CVE-2021-47483",
    "CVE-2021-47495",
    "CVE-2021-47496",
    "CVE-2021-47497",
    "CVE-2021-47501",
    "CVE-2021-47511",
    "CVE-2021-47516",
    "CVE-2021-47527",
    "CVE-2021-47541",
    "CVE-2021-47544",
    "CVE-2021-47565",
    "CVE-2021-47576",
    "CVE-2021-47579",
    "CVE-2021-47583",
    "CVE-2021-47588",
    "CVE-2021-47589",
    "CVE-2021-47597",
    "CVE-2021-47602",
    "CVE-2021-47606",
    "CVE-2021-47617",
    "CVE-2021-47619",
    "CVE-2022-48715",
    "CVE-2022-48732",
    "CVE-2022-48742",
    "CVE-2022-48743",
    "CVE-2022-48744",
    "CVE-2022-48747",
    "CVE-2022-48754",
    "CVE-2022-48757",
    "CVE-2022-48758",
    "CVE-2022-48760",
    "CVE-2022-48772",
    "CVE-2022-48775",
    "CVE-2022-48786",
    "CVE-2022-48788",
    "CVE-2022-48789",
    "CVE-2022-48790",
    "CVE-2022-48804",
    "CVE-2022-48809",
    "CVE-2022-48810",
    "CVE-2022-48823",
    "CVE-2022-48828",
    "CVE-2022-48836",
    "CVE-2022-48839",
    "CVE-2022-48843",
    "CVE-2022-48850",
    "CVE-2022-48855",
    "CVE-2022-48865",
    "CVE-2023-6536",
    "CVE-2023-47233",
    "CVE-2023-52683",
    "CVE-2023-52693",
    "CVE-2023-52698",
    "CVE-2023-52703",
    "CVE-2023-52707",
    "CVE-2023-52730",
    "CVE-2023-52741",
    "CVE-2023-52747",
    "CVE-2023-52752",
    "CVE-2023-52753",
    "CVE-2023-52754",
    "CVE-2023-52759",
    "CVE-2023-52762",
    "CVE-2023-52764",
    "CVE-2023-52796",
    "CVE-2023-52803",
    "CVE-2023-52809",
    "CVE-2023-52813",
    "CVE-2023-52832",
    "CVE-2023-52834",
    "CVE-2023-52843",
    "CVE-2023-52845",
    "CVE-2023-52847",
    "CVE-2023-52864",
    "CVE-2023-52868",
    "CVE-2023-52880",
    "CVE-2023-52881",
    "CVE-2024-23848",
    "CVE-2024-24859",
    "CVE-2024-27417",
    "CVE-2024-31076",
    "CVE-2024-33621",
    "CVE-2024-35789",
    "CVE-2024-35805",
    "CVE-2024-35807",
    "CVE-2024-35808",
    "CVE-2024-35809",
    "CVE-2024-35811",
    "CVE-2024-35835",
    "CVE-2024-35853",
    "CVE-2024-35855",
    "CVE-2024-35877",
    "CVE-2024-35886",
    "CVE-2024-35888",
    "CVE-2024-35893",
    "CVE-2024-35895",
    "CVE-2024-35896",
    "CVE-2024-35898",
    "CVE-2024-35904",
    "CVE-2024-35910",
    "CVE-2024-35925",
    "CVE-2024-35930",
    "CVE-2024-35947",
    "CVE-2024-35950",
    "CVE-2024-35960",
    "CVE-2024-35962",
    "CVE-2024-35969",
    "CVE-2024-35976",
    "CVE-2024-35984",
    "CVE-2024-35995",
    "CVE-2024-35997",
    "CVE-2024-36004",
    "CVE-2024-36006",
    "CVE-2024-36007",
    "CVE-2024-36015",
    "CVE-2024-36016",
    "CVE-2024-36017",
    "CVE-2024-36286",
    "CVE-2024-36883",
    "CVE-2024-36886",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36904",
    "CVE-2024-36905",
    "CVE-2024-36914",
    "CVE-2024-36917",
    "CVE-2024-36919",
    "CVE-2024-36924",
    "CVE-2024-36933",
    "CVE-2024-36938",
    "CVE-2024-36940",
    "CVE-2024-36941",
    "CVE-2024-36949",
    "CVE-2024-36950",
    "CVE-2024-36952",
    "CVE-2024-36954",
    "CVE-2024-36960",
    "CVE-2024-36971",
    "CVE-2024-37353",
    "CVE-2024-37356",
    "CVE-2024-38538",
    "CVE-2024-38552",
    "CVE-2024-38558",
    "CVE-2024-38559",
    "CVE-2024-38588",
    "CVE-2024-38596",
    "CVE-2024-38601",
    "CVE-2024-39276",
    "CVE-2024-39480",
    "CVE-2024-39487",
    "CVE-2024-39493",
    "CVE-2024-39494",
    "CVE-2024-39499",
    "CVE-2024-39501",
    "CVE-2024-40901",
    "CVE-2024-40904",
    "CVE-2024-40960",
    "CVE-2024-40978",
    "CVE-2024-40984",
    "CVE-2024-40995",
    "CVE-2024-40998",
    "CVE-2024-41005",
    "CVE-2024-41007"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"EulerOS 2.0 SP9 : kernel (EulerOS-SA-2024-2394)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    kernel:ACPI: CPPC: Use access_width over bit_width for system memory accesses(CVE-2024-35995)

    ACPI: LPIT: Avoid u32 multiplication overflow(CVE-2023-52683)

    ACPI: video: check for error while searching for backlight device parent(CVE-2023-52693)

    bpf: Fix stackmap overflow check on 32-bit arches(CVE-2024-36949)

    kernel: block: fix overflow in blk_ioctl_discard()(CVE-2024-36917)

    kernel:block: prevent division by zero in blk_rq_stat_sum()(CVE-2024-35925)

    bpf, skmsg: Fix NULL pointer dereference in sk_psock_skb_ingress_enqueue(CVE-2024-36938)

    bpf, sockmap: Prevent lock inversion deadlock in map delete elem(CVE-2024-35895)

    kernel:calipso: fix memory leak in netlbl_calipso_add_pass()(CVE-2023-52698)

    drm/amd/display: Avoid NULL dereference of timing generator(CVE-2023-52753)

    drm/amd/display: Skip on writeback when it's not applicable(CVE-2024-36914)

    kernel:erspan: make sure erspan_base_hdr is present in skb-head(CVE-2024-35888)

    kernel: ext4: fix corruption during on-line resize(CVE-2024-35807)

    kernel: ext4: fix possible UAF when remounting r/o a mmp-protected file system(CVE-2021-47342)

    firewire: ohci: mask bus reset interrupts between ISR and bottom half(CVE-2024-36950)

    gfs2: ignore negated quota changes(CVE-2023-52759)

    kernel:HID: i2c-hid: remove I2C_HID_READ_PENDING flag to prevent lock-up(CVE-2024-35997)

    kernel:i2c: smbus: fix NULL function pointer dereference(CVE-2024-35984)

    kernel:i40e: Do not use WQ_MEM_RECLAIM flag for workqueue(CVE-2024-36004)

    kernel:ipv6: fib6_rules: avoid possible NULL dereference in fib6_rule_action()(CVE-2024-36902)

    kernel:ipv6: Fix infinite recursion in fib6_dump_done().(CVE-2024-35886)

    kernel:ipv6: prevent NULL dereference in ip6_output()(CVE-2024-36901)

    kernel:ipvlan: add ipvlan_route_v6_outbound() helper(CVE-2023-52796)

    kernel: md/dm-raid: don#39;t call md_reap_sync_thread() directly(CVE-2024-35808)

    media: bttv: fix use after free error due to btv-timeout timer(CVE-2023-52847)

    media: gspca: cpia1: shift-out-of-bounds in set_flicker(CVE-2023-52764)

    mlxsw: spectrum_acl_tcam: Fix possible use-after-free during activity update(CVE-2024-35855)

    mlxsw: spectrum_acl_tcam: Fix warning during rehash(CVE-2024-36007)

    kernel:net/mlx5: Properly link new fs rules into the tree(CVE-2024-35960)

    kernel:net/mlx5e: fix a double-free in arfs_create_groups(CVE-2024-35835)

    kernel:net: fix __dst_negative_advice() race(CVE-2024-36971)

    kernel:net: fix out-of-bounds access in ops_init(CVE-2024-36883)

    kernel:netfilter: validate user input for expected length(CVE-2024-35896)

    NFS: fs_context: validate UDP retrans to prevent shift out-of-bounds(CVE-2021-46952)

    nsh: Restore skb-{protocol,data,mac_header} for outer header in nsh_gso_segment().(CVE-2024-36933)

    nvmem: Fix shift-out-of-bound (UBSAN) with byte size cells(CVE-2021-47497)

    kernel: PCI/PM: Drain runtime-idle callbacks before driver removal(CVE-2024-35809)

    kernel: pinctrl: core: delete incorrect free in pinctrl_enable()(CVE-2024-36940)

    platform/x86: wmi: Fix opening of char device(CVE-2023-52864)

    ppdev: Add an error check in register_device(CVE-2024-36015)

    kernel:RDMA: Verify port when creating flow rule(CVE-2021-47265)

    kernel:ring-buffer: Fix a race between readers and resize checks(CVE-2024-38601)

    kernel: scsi: bnx2fc: Remove spin_lock_bh while releasing resources after upload(CVE-2024-36919)

    kernel:scsi: iscsi: Fix iscsi_task use after free(CVE-2021-47427)

    kernel:scsi: lpfc: Release hbalock before calling lpfc_worker_wake_up()(CVE-2024-36924)

    kernel: selinux: avoid dereference of garbage after mount failure(CVE-2024-35904)

    kernel: smb: client: fix use-after-free bug in cifs_debug_data_proc_show()(CVE-2023-52752)

    kernel:tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets(CVE-2024-36905)

    kernel:tcp: properly terminate timers for kernel sockets(CVE-2024-35910)

    kernel:tcp: Use refcount_inc_not_zero() in tcp_twsk_unique().(CVE-2024-36904)

    kernel: thermal: core: prevent potential string overflow(CVE-2023-52868)

    tipc: fix a possible memleak in tipc_buf_append(CVE-2024-36954)

    tipc: fix UAF in error path(CVE-2024-36886)

    kernel:tty: n_gsm: fix possible out-of-bounds in gsm0_receive()(CVE-2024-36016)

    virtio-blk: fix implicit overflow on virtio_max_dma_size(CVE-2023-52762)

    wifi: mac80211: don't return unset power in ieee80211_get_tx_power()(CVE-2023-52832)

    kernel:llc: verify mac len before reading mac header(CVE-2023-52843)

    x86/mm/pat: fix VM_PAT handling in COW mappings(CVE-2024-35877)

    drm/client: Fully protect modes[] with dev-mode_config.mutex(CVE-2024-35950)

    mlxsw: spectrum_acl_tcam: Fix incorrect list API usage(CVE-2024-36006)

    net: bridge: fix vlan tunnel dst refcnt when egressing(CVE-2021-47222)

    net: bridge: fix vlan tunnel dst null pointer dereference(CVE-2021-47223)

    KVM: x86: Immediately reset the MMU context when the SMM flag is cleared(CVE-2021-47230)

    kernel:net: cdc_eem: fix tx fixup skb leak(CVE-2021-47236)

    net: ipv4: fix memory leak in ip_mc_add1_src(CVE-2021-47238)

    netfilter: synproxy: Fix out of bounds when parsing TCP options(CVE-2021-47245)

    udp: fix race between close() and udp_abort()(CVE-2021-47248)

    net: ipv4: fix memory leak in netlbl_cipsov4_add_std(CVE-2021-47250)

    kvm: LAPIC: Restore guard to prevent illegal APIC register access(CVE-2021-47255)

    NFS: Fix use-after-free in nfs4_init_client()(CVE-2021-47259)

    kernel: IB/mlx5: Fix initializing CQ fragments buffer(CVE-2021-47261)

    ftrace: Do not blindly read the ip address in ftrace_bug()(CVE-2021-47276)

    kernel:kvm: avoid speculation-based attacks from out-of-range memslot accesses(CVE-2021-47277)

    kernel: drm: Fix use-after-free read in drm_getunique()(CVE-2021-47280)

    isdn: mISDN: netjet: Fix crash in nj_probe(CVE-2021-47284)

    media: ngene: Fix out-of-bounds bug in ngene_command_config_free_buf()(CVE-2021-47288)

    net/sched: act_skbmod: Skip non-Ethernet packets(CVE-2021-47293)

    kernel:igb: Fix use-after-free error during reset(CVE-2021-47301)

    igc: Fix use-after-free error during reset(CVE-2021-47302)

    scsi: libfc: Fix array index out of bound exception(CVE-2021-47308)

    virtio-blk: Fix memory leak among suspend/resume procedure(CVE-2021-47319)

    scsi: iscsi: Fix conn use after free during resets(CVE-2021-47328)

    kernel:scsi: megaraid_sas: Fix resource leak in case of probe failure(CVE-2021-47329)

    KVM: mmio: Fix use-after-free Read in kvm_vm_ioctl_unregister_coalesced_mmio(CVE-2021-47341)

    kernel: udf: Fix NULL pointer dereference in udf_symlink function(CVE-2021-47353)

    bpf: Add oversize check before call kvcalloc()(CVE-2021-47376)

    mac80211: limit injected vht mcs
    ss in ieee80211_parse_tx_radiotap(CVE-2021-47395)

    kernel:sctp: break out if skb_header_pointer returns NULL in sctp_rcv_ootb(CVE-2021-47397)

    ixgbe: Fix NULL pointer dereference in ixgbe_xdp_setup(CVE-2021-47399)

    HID: usbhid: free raw_report buffers in usbhid_stop(CVE-2021-47405)

    KVM: x86: Handle SRCU initialization failure during page track init(CVE-2021-47407)

    phy: mdio: fix memory leak(CVE-2021-47416)

    net_sched: fix NULL deref in fifo_set_limit()(CVE-2021-47418)

    i40e: Fix freeing of uninitialized misc IRQ vector(CVE-2021-47424)

    kernel:i2c: acpi: fix resource leak in reconfiguration device addition(CVE-2021-47425)

    xhci: Fix command ring pointer corruption while aborting a command(CVE-2021-47434)

    kernel:net/mlx5e: Fix memory leak in mlx5_core_destroy_cq() error path(CVE-2021-47438)

    can: peak_pci: peak_pci_remove(): fix UAF(CVE-2021-47456)

    audit: fix possible null-pointer dereference in audit_filter_rules(CVE-2021-47464)

    kernel: mm, slub: fix potential memoryleak in kmem_cache_open()(CVE-2021-47466)

    isdn: mISDN: Fix sleeping function called from invalid context(CVE-2021-47468)

    kernel: scsi: qla2xxx: Fix a memory leak in an error path of qla2x00_process_els()(CVE-2021-47473)

    kernel: isofs: Fix out of bound access for corrupted isofs image(CVE-2021-47478)

    kernel:regmap: Fix possible double-free in regcache_rbtree_exit()(CVE-2021-47483)

    kernel:usbnet: sanity check for maxpacket(CVE-2021-47495)

    net/tls: Fix flipped sign in tls_err_abort() calls(CVE-2021-47496)

    kernel:i40e: Fix NULL pointer dereference in i40e_dbg_dump_desc(CVE-2021-47501)

    ALSA: pcm: oss: Fix negative period/buffer sizes(CVE-2021-47511)

    kernel:nfp: Fix memory leak in nfp_cpp_area_cache_add()(CVE-2021-47516)

    serial: core: fix transmit-buffer reset and memleak(CVE-2021-47527)

    kernel:net/mlx4_en: Fix an use-after-free bug in mlx4_en_try_alloc_resources()(CVE-2021-47541)

    tcp: fix page frag corruption on page fault(CVE-2021-47544)

    kernel: scsi: mpt3sas: Fix kernel panic during drive powercycle test(CVE-2021-47565)

    scsi: scsi_debug: Sanity check block descriptor length in resp_mode_select()(CVE-2021-47576)

    ovl: fix warning in ovl_create_real()(CVE-2021-47579)

    media: mxl111sf: change mutex_init() location(CVE-2021-47583)

    sit: do not call ipip6_dev_free() from sit_init_net()(CVE-2021-47588)

    igbvf: fix double free in `igbvf_probe`(CVE-2021-47589)

    kernel:inet_diag: fix kernel-infoleak for UDP sockets(CVE-2021-47597)

    mac80211: track only QoS data frames for admission control(CVE-2021-47602)

    net: netlink: af_netlink: Prevent empty skb by adding a check on len.(CVE-2021-47606)

    PCI: pciehp: Fix infinite loop in IRQ handler upon power fault(CVE-2021-47617)

    kernel:i40e: Fix queues reservation for XDP(CVE-2021-47619)

    kernel: scsi: bnx2fc: Make bnx2fc_recv_frame() mp safe(CVE-2022-48715)

    drm
    ouveau: fix off by one in BIOS boundary checking(CVE-2022-48732)

    rtnetlink: make sure to refresh master_dev/m_ops in __rtnl_newlink()(CVE-2022-48742)

    net: amd-xgbe: Fix skb data length underflow(CVE-2022-48743)

    kernel:net/mlx5e: Avoid field-overflowing memcpy()(CVE-2022-48744)

    kernel:block: Fix wrong offset in bio_truncate()(CVE-2022-48747)

    phylib: fix potential use-after-free(CVE-2022-48754)

    net: fix information leakage in /proc/net/ptype(CVE-2022-48757)

    scsi: bnx2fc: Flush destroy_work queue before calling bnx2fc_interface_put()(CVE-2022-48758)

    USB: core: Fix hang in usb_kill_urb by adding memory barriers(CVE-2022-48760)

    media: lgdt3306a: Add a check against null-pointer-def(CVE-2022-48772)

    Drivers: hv: vmbus: Fix memory leak in vmbus_add_channel_kobj(CVE-2022-48775)

    vsock: remove vsock from connected table when connect is interrupted by a signal(CVE-2022-48786)

    nvme-rdma: fix possible use-after-free in transport error_recovery work(CVE-2022-48788)

    nvme-tcp: fix possible use-after-free in transport error_recovery work(CVE-2022-48789)

    nvme: fix a possible use-after-free in controller reset during load(CVE-2022-48790)

    kernel:vt_ioctl: fix array_index_nospec in vt_setactivate(CVE-2022-48804)

    net: fix a memleak when uncloning an skb dst and its metadata(CVE-2022-48809)

    ipmr,ip6mr: acquire RTNL before calling ip[6]mr_free_table() on failure path(CVE-2022-48810)

    scsi: qedf: Fix refcount issue when LOGO is received during TMF(CVE-2022-48823)

    NFSD: Fix ia_size underflow(CVE-2022-48828)

    Input: aiptek - properly check endpoint type(CVE-2022-48836)

    net/packet: fix slab-out-of-bounds access in packet_recvmsg()(CVE-2022-48839)

    drm/vrr: Set VRR capable prop only if it is attached to connector(CVE-2022-48843)

    net-sysfs: add check for netdevice being present to speed_show(CVE-2022-48850)

    kernel:sctp: fix kernel-infoleak for SCTP sockets(CVE-2022-48855)

    tipc: fix kernel panic when enabling bearer(CVE-2022-48865)

    The brcm80211 component in the Linux kernel through 6.5.10 has a brcmf_cfg80211_detach use-after-free in
    the device unplugging (disconnect the USB by hotplug) code. For physically proximate attackers with local
    access, this 'could be exploited in a real world scenario.' This is related to
    brcmf_cfg80211_escan_timeout_worker in
    drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c.(CVE-2023-47233)

    kernel:net/usb: kalmia: Don't pass act_len in usb_bulk_msg error path(CVE-2023-52703)

    sched/psi: Fix use-after-free in ep_remove_wait_queue()(CVE-2023-52707)

    mmc: sdio: fix possible resource leaks in some error paths(CVE-2023-52730)

    cifs: Fix use-after-free in rdata-read_into_pages()(CVE-2023-52741)

    IB/hfi1: Restore allocated resources on failed copyout(CVE-2023-52747)

    media: imon: fix access to invalid resource for the second interface(CVE-2023-52754)

    kernel:SUNRPC: Fix RPC client cleaned up the freed pipefs dentries(CVE-2023-52803)

    scsi: libfc: Fix potential NULL pointer dereference in fc_lport_ptp_setup()(CVE-2023-52809)

    kernel: crypto: pcrypt - Fix hungtask for PADATA_RESET(CVE-2023-52813)

    atl1c: Work around the DMA RX overflow issue(CVE-2023-52834)

    tipc: Change nla_policy for bearer-related names to NLA_NUL_STRING(CVE-2023-52845)

    tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc(CVE-2023-52880)

    kernel:tcp: do not accept ACK of bytes we never sent(CVE-2023-52881)

    A flaw was found in the Linux kernel's NVMe driver. This issue may allow an unauthenticated malicious
    actor to send a set of crafted TCP packages when using NVMe over TCP, leading the NVMe driver to a NULL
    pointer dereference in the NVMe driver, causing kernel panic and a denial of service.(CVE-2023-6536)

    In the Linux kernel through 6.7.1, there is a use-after-free in cec_queue_msg_fh, related to
    drivers/media/cec/core/cec-adap.c and drivers/media/cec/core/cec-api.c.(CVE-2024-23848)

    A race condition was found in the Linux kernel's net/bluetooth in sniff_{min,max}_interval_set() function.
    This can result in a bluetooth sniffing exception issue, possibly leading denial of
    service.(CVE-2024-24859)

    ipv6: fix potential 'struct net' leak in inet6_rtm_getaddr()(CVE-2024-27417)

    genirq/cpuhotplug, x86/vector: Prevent vector leak during CPU offline(CVE-2024-31076)

    ipvlan: Dont Use skb-sk in ipvlan_process_v{4,6}_outbound(CVE-2024-33621)

    kernel: wifi: mac80211: check/clear fast rx for non-4addr sta VLAN changes(CVE-2024-35789)

    kernel:fix lockup in dm_exception_table_exit  There was reported lockup(CVE-2024-35805)

    wifi: brcmfmac: Fix use-after-free bug in brcmf_cfg80211_detach(CVE-2024-35811)

    mlxsw: spectrum_acl_tcam: Fix memory leak during rehash(CVE-2024-35853)

    net/sched: act_skbmod: prevent kernel-infoleak(CVE-2024-35893)

    netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get()(CVE-2024-35898)

    kernel:scsi: lpfc: Fix possible memory leak in lpfc_rcv_padisc()  (CVE-2024-35930)

    dyndbg: fix old BUG_ON in control parser(CVE-2024-35947)

    kernel:netfilter: complete validation of user input(CVE-2024-35962)

    kernel:ipv6: fix race condition between ipv6_get_ifaddr and ipv6_del_addr(CVE-2024-35969)

    xsk: validate user input for XDP_{UMEM|COMPLETION}_FILL_RING(CVE-2024-35976)

    rtnetlink: Correct nested IFLA_VF_VLAN_LIST attribute validation(CVE-2024-36017)

    netfilter: nfnetlink_queue: acquire rcu_read_lock() in instance_destroy_rcu()(CVE-2024-36286)

    wifi: nl80211: don't free NULL coalescing rule(CVE-2024-36941)

    kernel: scsi: lpfc: Move NPIV's transport unregistration to after resource clean up(CVE-2024-36952)

    drm/vmwgfx: Fix invalid reads in fence signaled events(CVE-2024-36960)

    kernel:virtio: delete vq in vp_find_vqs_msix() when request_irq() fails(CVE-2024-37353)

    kernel:tcp: Fix shift-out-of-bounds in dctcp_update_alpha().(CVE-2024-37356)

    kernel:net: bridge: xmit: make sure we have at least eth header len bytes(CVE-2024-38538)

    drm/amd/display: Fix potential index out of bounds in color transformation function(CVE-2024-38552)

    net: openvswitch: fix overwriting ct original tuple for ICMPv6(CVE-2024-38558)

    kernel:scsi: qedf: Ensure the copied buf is NUL terminated(CVE-2024-38559)

    kernel:ftrace: Fix possible use-after-free issue in ftrace_location()(CVE-2024-38588)

    kernel:af_unix: Fix data races in unix_release_sock/unix_stream_sendmsg(CVE-2024-38596)

    kernel: ext4: fix mb_cache_entry#39;s e_refcnt leak in ext4_xattr_block_cache_find()(CVE-2024-39276)

    kernel:kdb: Fix buffer overflow during tab-complete(CVE-2024-39480)

    kernel:bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set()(CVE-2024-39487)

    crypto: qat - Fix ADF_DEV_RESET_SYNC memory leak(CVE-2024-39493)

    kernel:ima: Fix use-after-free on a dentry's dname.name(CVE-2024-39494)

    vmci: prevent speculation leaks by sanitizing event in event_deliver()(CVE-2024-39499)

    drivers: core: synchronize really_probe() and dev_uevent()(CVE-2024-39501)

    scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory(CVE-2024-40901)

    kernel:USB: class: cdc-wdm: Fix CPU lockup caused by excessive log messages(CVE-2024-40904)

    kernel:ipv6: prevent possible NULL dereference in rt6_probe()(CVE-2024-40960)

    scsi: qedi: Fix crash while reading debugfs attribute(CVE-2024-40978)

    kernel:ACPICA: Revert 'ACPICA: avoid Info: mapping multiple BARs. Your kernel is fine.(CVE-2024-40984)

    kernel:net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc()(CVE-2024-40995)

    kernel:ext4: fix uninitialized ratelimit_state-lock access in __ext4_fill_super()(CVE-2024-40998)

    kernel:netpoll: Fix race condition in netpoll_owner_active(CVE-2024-41005)

    kernel:tcp: avoid too many retransmit packets(CVE-2024-41007)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2394
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5086fb2e");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39494");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.18.0-147.5.1.6.h1402.eulerosv2r9",
  "kernel-tools-4.18.0-147.5.1.6.h1402.eulerosv2r9",
  "kernel-tools-libs-4.18.0-147.5.1.6.h1402.eulerosv2r9",
  "python3-perf-4.18.0-147.5.1.6.h1402.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
