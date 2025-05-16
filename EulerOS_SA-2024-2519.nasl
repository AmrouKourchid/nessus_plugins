#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208351);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2019-25162",
    "CVE-2021-47183",
    "CVE-2021-47200",
    "CVE-2021-47247",
    "CVE-2021-47265",
    "CVE-2021-47334",
    "CVE-2021-47341",
    "CVE-2021-47427",
    "CVE-2021-47432",
    "CVE-2021-47469",
    "CVE-2021-47552",
    "CVE-2021-47582",
    "CVE-2021-47617",
    "CVE-2021-47619",
    "CVE-2022-48639",
    "CVE-2022-48652",
    "CVE-2022-48654",
    "CVE-2022-48672",
    "CVE-2022-48686",
    "CVE-2022-48695",
    "CVE-2022-48713",
    "CVE-2022-48714",
    "CVE-2022-48715",
    "CVE-2022-48717",
    "CVE-2022-48728",
    "CVE-2022-48738",
    "CVE-2022-48742",
    "CVE-2022-48744",
    "CVE-2022-48745",
    "CVE-2022-48746",
    "CVE-2022-48747",
    "CVE-2022-48754",
    "CVE-2022-48755",
    "CVE-2022-48761",
    "CVE-2022-48765",
    "CVE-2022-48767",
    "CVE-2022-48768",
    "CVE-2022-48769",
    "CVE-2022-48770",
    "CVE-2022-48771",
    "CVE-2022-48772",
    "CVE-2022-48775",
    "CVE-2022-48786",
    "CVE-2022-48804",
    "CVE-2022-48805",
    "CVE-2022-48809",
    "CVE-2022-48810",
    "CVE-2022-48816",
    "CVE-2022-48843",
    "CVE-2022-48848",
    "CVE-2022-48853",
    "CVE-2022-48855",
    "CVE-2022-48865",
    "CVE-2023-52501",
    "CVE-2023-52653",
    "CVE-2023-52672",
    "CVE-2023-52679",
    "CVE-2023-52708",
    "CVE-2023-52730",
    "CVE-2023-52732",
    "CVE-2023-52735",
    "CVE-2023-52736",
    "CVE-2023-52741",
    "CVE-2023-52743",
    "CVE-2023-52745",
    "CVE-2023-52747",
    "CVE-2023-52752",
    "CVE-2023-52754",
    "CVE-2023-52757",
    "CVE-2023-52762",
    "CVE-2023-52781",
    "CVE-2023-52784",
    "CVE-2023-52790",
    "CVE-2023-52807",
    "CVE-2023-52831",
    "CVE-2023-52835",
    "CVE-2023-52836",
    "CVE-2023-52853",
    "CVE-2023-52859",
    "CVE-2023-52881",
    "CVE-2024-26846",
    "CVE-2024-26873",
    "CVE-2024-26880",
    "CVE-2024-26910",
    "CVE-2024-26917",
    "CVE-2024-26935",
    "CVE-2024-26953",
    "CVE-2024-27017",
    "CVE-2024-27020",
    "CVE-2024-27062",
    "CVE-2024-27065",
    "CVE-2024-27388",
    "CVE-2024-27397",
    "CVE-2024-27403",
    "CVE-2024-27415",
    "CVE-2024-27417",
    "CVE-2024-31076",
    "CVE-2024-34777",
    "CVE-2024-35790",
    "CVE-2024-35805",
    "CVE-2024-35808",
    "CVE-2024-35809",
    "CVE-2024-35823",
    "CVE-2024-35839",
    "CVE-2024-35852",
    "CVE-2024-35853",
    "CVE-2024-35854",
    "CVE-2024-35855",
    "CVE-2024-35870",
    "CVE-2024-35877",
    "CVE-2024-35879",
    "CVE-2024-35886",
    "CVE-2024-35888",
    "CVE-2024-35893",
    "CVE-2024-35895",
    "CVE-2024-35896",
    "CVE-2024-35897",
    "CVE-2024-35899",
    "CVE-2024-35900",
    "CVE-2024-35904",
    "CVE-2024-35905",
    "CVE-2024-35910",
    "CVE-2024-35924",
    "CVE-2024-35925",
    "CVE-2024-35930",
    "CVE-2024-35939",
    "CVE-2024-35947",
    "CVE-2024-35950",
    "CVE-2024-35955",
    "CVE-2024-35958",
    "CVE-2024-35960",
    "CVE-2024-35962",
    "CVE-2024-35969",
    "CVE-2024-35973",
    "CVE-2024-35984",
    "CVE-2024-35989",
    "CVE-2024-35995",
    "CVE-2024-35997",
    "CVE-2024-36000",
    "CVE-2024-36004",
    "CVE-2024-36005",
    "CVE-2024-36007",
    "CVE-2024-36015",
    "CVE-2024-36016",
    "CVE-2024-36020",
    "CVE-2024-36021",
    "CVE-2024-36031",
    "CVE-2024-36478",
    "CVE-2024-36489",
    "CVE-2024-36883",
    "CVE-2024-36886",
    "CVE-2024-36898",
    "CVE-2024-36899",
    "CVE-2024-36900",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36903",
    "CVE-2024-36904",
    "CVE-2024-36905",
    "CVE-2024-36908",
    "CVE-2024-36916",
    "CVE-2024-36917",
    "CVE-2024-36919",
    "CVE-2024-36923",
    "CVE-2024-36924",
    "CVE-2024-36927",
    "CVE-2024-36933",
    "CVE-2024-36938",
    "CVE-2024-36939",
    "CVE-2024-36940",
    "CVE-2024-36950",
    "CVE-2024-36952",
    "CVE-2024-36953",
    "CVE-2024-36954",
    "CVE-2024-36959",
    "CVE-2024-36960",
    "CVE-2024-36964",
    "CVE-2024-36971",
    "CVE-2024-36978",
    "CVE-2024-37353",
    "CVE-2024-37356",
    "CVE-2024-38538",
    "CVE-2024-38540",
    "CVE-2024-38541",
    "CVE-2024-38544",
    "CVE-2024-38552",
    "CVE-2024-38555",
    "CVE-2024-38556",
    "CVE-2024-38558",
    "CVE-2024-38559",
    "CVE-2024-38564",
    "CVE-2024-38577",
    "CVE-2024-38588",
    "CVE-2024-38596",
    "CVE-2024-38598",
    "CVE-2024-38601",
    "CVE-2024-38608",
    "CVE-2024-38615",
    "CVE-2024-38619",
    "CVE-2024-38632",
    "CVE-2024-38662",
    "CVE-2024-39276",
    "CVE-2024-39277",
    "CVE-2024-39472",
    "CVE-2024-39476",
    "CVE-2024-39480",
    "CVE-2024-39487",
    "CVE-2024-39493",
    "CVE-2024-39499",
    "CVE-2024-39500",
    "CVE-2024-39503",
    "CVE-2024-39508",
    "CVE-2024-39510",
    "CVE-2024-40899",
    "CVE-2024-40904",
    "CVE-2024-40905",
    "CVE-2024-40913",
    "CVE-2024-40934",
    "CVE-2024-40935",
    "CVE-2024-40956",
    "CVE-2024-40960",
    "CVE-2024-40972",
    "CVE-2024-40980",
    "CVE-2024-40983",
    "CVE-2024-40984",
    "CVE-2024-40990",
    "CVE-2024-40995",
    "CVE-2024-40998",
    "CVE-2024-41005",
    "CVE-2024-41007",
    "CVE-2024-41009"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"EulerOS 2.0 SP12 : kernel (EulerOS-SA-2024-2519)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    bpf, skmsg: Fix NULL pointer dereference in sk_psock_skb_ingress_enqueue(CVE-2024-36938)

    bpf, sockmap: Prevent lock inversion deadlock in map delete elem(CVE-2024-35895)

    cifs: Fix use-after-free in rdata-read_into_pages()(CVE-2023-52741)

    crypto: qat - Fix ADF_DEV_RESET_SYNC memory leak(CVE-2024-39493)

    Drivers: hv: vmbus: Fix memory leak in vmbus_add_channel_kobj(CVE-2022-48775)

    drm/amd/display: Fix potential index out of bounds in color transformation function(CVE-2024-38552)

    drm/client: Fully protect modes[] with dev-mode_config.mutex(CVE-2024-35950)

    drm/vmwgfx: Fix invalid reads in fence signaled events(CVE-2024-36960)

    drm/vrr: Set VRR capable prop only if it is attached to connector(CVE-2022-48843)

    dyndbg: fix old BUG_ON in control parser(CVE-2024-35947)

    firewire: ohci: mask bus reset interrupts between ISR and bottom half(CVE-2024-36950)

    genirq/cpuhotplug, x86/vector: Prevent vector leak during CPU offline(CVE-2024-31076)

    i2c: Fix a potential use after free(CVE-2019-25162)

    IB/hfi1: Restore allocated resources on failed copyout(CVE-2023-52747)

    ipmr,ip6mr: acquire RTNL before calling ip[6]mr_free_table() on failure path(CVE-2022-48810)

    ipv6: fix potential 'struct net' leak in inet6_rtm_getaddr()(CVE-2024-27417)

    kernel: block: fix overflow in blk_ioctl_discard()(CVE-2024-36917)

    kernel: cpu/hotplug: Don't offline the last non-isolated CPU(CVE-2023-52831)

    kernel: ext4: fix mb_cache_entry#39;s e_refcnt leak in ext4_xattr_block_cache_find()(CVE-2024-39276)

    kernel: md/dm-raid: don#39;t call md_reap_sync_thread() directly(CVE-2024-35808)

    kernel: mmc: mmc_spi: fix error handling in mmc_spi_probe()(CVE-2023-52708)

    kernel: PCI/PM: Drain runtime-idle callbacks before driver removal(CVE-2024-35809)

    kernel: perf/core: Bail out early if the request AUX area is out of bound(CVE-2023-52835)

    kernel: pinctrl: core: delete incorrect free in pinctrl_enable()(CVE-2024-36940)

    kernel: scsi: bnx2fc: Make bnx2fc_recv_frame() mp safe(CVE-2022-48715)

    kernel: scsi: bnx2fc: Remove spin_lock_bh while releasing resources after upload(CVE-2024-36919)

    kernel: scsi: lpfc: Move NPIV's transport unregistration to after resource clean up(CVE-2024-36952)

    kernel: scsi: mpt3sas: Fix use-after-free warning(CVE-2022-48695)

    kernel: selinux: avoid dereference of garbage after mount failure(CVE-2024-35904)

    kernel: smb: client: fix use-after-free bug in cifs_debug_data_proc_show()(CVE-2023-52752)

    kernel:ACPI: CPPC: Use access_width over bit_width for system memory accesses(CVE-2024-35995)

    kernel:ACPICA: Revert 'ACPICA: avoid Info: mapping multiple BARs. Your kernel is fine.(CVE-2024-40984)

    kernel:af_unix: Fix data races in unix_release_sock/unix_stream_sendmsg(CVE-2024-38596)

    kernel:block: Fix wrong offset in bio_truncate()(CVE-2022-48747)

    kernel:block: prevent division by zero in blk_rq_stat_sum()(CVE-2024-35925)

    kernel:bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set()(CVE-2024-39487)

    kernel:dm: call the resume method on internal suspend(CVE-2024-26880)

    kernel:erspan: make sure erspan_base_hdr is present in skb-head(CVE-2024-35888)

    kernel:ext4: fix uninitialized ratelimit_state-lock access in __ext4_fill_super()(CVE-2024-40998)

    kernel:fix lockup in dm_exception_table_exit  There was reported lockup(CVE-2024-35805)

    kernel:ftrace: Fix possible use-after-free issue in ftrace_location()(CVE-2024-38588)

    kernel:HID: i2c-hid: remove I2C_HID_READ_PENDING flag to prevent lock-up(CVE-2024-35997)

    kernel:i2c: smbus: fix NULL function pointer dereference(CVE-2024-35984)

    kernel:i40e: Do not use WQ_MEM_RECLAIM flag for workqueue(CVE-2024-36004)

    kernel:i40e: Fix queues reservation for XDP(CVE-2021-47619)

    kernel:ipv6: fib6_rules: avoid possible NULL dereference in fib6_rule_action()(CVE-2024-36902)

    kernel:ipv6: Fix infinite recursion in fib6_dump_done().(CVE-2024-35886)

    kernel:ipv6: Fix potential uninit-value access in __ip6_make_skb()(CVE-2024-36903)

    kernel:ipv6: fix race condition between ipv6_get_ifaddr and ipv6_del_addr(CVE-2024-35969)

    kernel:ipv6: prevent NULL dereference in ip6_output()(CVE-2024-36901)

    kernel:ipv6: prevent possible NULL dereference in rt6_probe()(CVE-2024-40960)

    kernel:kdb: Fix buffer overflow during tab-complete(CVE-2024-39480)

    kernel:kprobes: Fix possible use-after-free issue on kprobe registration(CVE-2024-35955)

    kernel:net/mlx5: Properly link new fs rules into the tree(CVE-2024-35960)

    kernel:net/mlx5e: Avoid field-overflowing memcpy()(CVE-2022-48744)

    kernel:net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc()(CVE-2024-40995)

    kernel:net: bridge: xmit: make sure we have at least eth header len bytes(CVE-2024-38538)

    kernel:net: fix __dst_negative_advice() race(CVE-2024-36971)

    kernel:net: fix out-of-bounds access in ops_init(CVE-2024-36883)

    kernel:netfilter: complete validation of user input(CVE-2024-35962)

    kernel:netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get()(CVE-2024-27020)

    kernel:netfilter: validate user input for expected length(CVE-2024-35896)

    kernel:netpoll: Fix race condition in netpoll_owner_active(CVE-2024-41005)

    kernel:nouveau: lock the client object tree. (CVE-2024-27062)

    kernel:nvme-fc: do not wait in vain when unloading module(CVE-2024-26846)

    kernel:of: Fix double free in of_parse_phandle_with_args_map(CVE-2023-52679)

    kernel:of: module: add buffer overflow check in of_modalias()(CVE-2024-38541)

    kernel:RDMA: Verify port when creating flow rule(CVE-2021-47265)

    kernel:ring-buffer: Fix a race between readers and resize checks(CVE-2024-38601)

    kernel:scsi: iscsi: Fix iscsi_task use after free(CVE-2021-47427)

    kernel:scsi: lpfc: Fix link down processing to address NULL pointer dereference(CVE-2021-47183)

    kernel:scsi: lpfc: Fix possible memory leak in lpfc_rcv_padisc()  (CVE-2024-35930)

    kernel:scsi: lpfc: Release hbalock before calling lpfc_worker_wake_up()(CVE-2024-36924)

    kernel:scsi: qedf: Ensure the copied buf is NUL terminated(CVE-2024-38559)

    kernel:sctp: fix kernel-infoleak for SCTP sockets(CVE-2022-48855)

    kernel:spi: Fix deadlock when adding SPI controllers on SPI buses(CVE-2021-47469)

    kernel:SUNRPC: fix a memleak in gss_import_v2_context(CVE-2023-52653)

    kernel:SUNRPC: fix some memleaks in gssx_dec_option_array(CVE-2024-27388)

    kernel:tcp: avoid too many retransmit packets(CVE-2024-41007)

    kernel:tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets(CVE-2024-36905)

    kernel:tcp: do not accept ACK of bytes we never sent(CVE-2023-52881)

    kernel:tcp: Fix shift-out-of-bounds in dctcp_update_alpha().(CVE-2024-37356)

    kernel:tcp: properly terminate timers for kernel sockets(CVE-2024-35910)

    kernel:tcp: Use refcount_inc_not_zero() in tcp_twsk_unique().(CVE-2024-36904)

    kernel:tty: n_gsm: fix possible out-of-bounds in gsm0_receive()(CVE-2024-36016)

    kernel:USB: class: cdc-wdm: Fix CPU lockup caused by excessive log messages(CVE-2024-40904)

    kernel:virtio: delete vq in vp_find_vqs_msix() when request_irq() fails(CVE-2024-37353)

    kernel:vt: fix unicode buffer corruption when deleting characters(CVE-2024-35823)

    kernel:vt_ioctl: fix array_index_nospec in vt_setactivate(CVE-2022-48804)

    KVM: mmio: Fix use-after-free Read in kvm_vm_ioctl_unregister_coalesced_mmio(CVE-2021-47341)

    media: imon: fix access to invalid resource for the second interface(CVE-2023-52754)

    media: lgdt3306a: Add a check against null-pointer-def(CVE-2022-48772)

    mlxsw: spectrum_acl_tcam: Fix memory leak during rehash(CVE-2024-35853)

    mlxsw: spectrum_acl_tcam: Fix possible use-after-free during activity update(CVE-2024-35855)

    mlxsw: spectrum_acl_tcam: Fix warning during rehash(CVE-2024-36007)

    mmc: sdio: fix possible resource leaks in some error paths(CVE-2023-52730)

    net/packet: fix slab-out-of-bounds access in packet_recvmsg()(CVE-2022-48839)

    net/sched: act_skbmod: prevent kernel-infoleak(CVE-2024-35893)

    net: fix a memleak when uncloning an skb dst and its metadata(CVE-2022-48809)

    net: openvswitch: fix overwriting ct original tuple for ICMPv6(CVE-2024-38558)

    nsh: Restore skb-{protocol,data,mac_header} for outer header in nsh_gso_segment().(CVE-2024-36933)

    PCI: pciehp: Fix infinite loop in IRQ handler upon power fault(CVE-2021-47617)

    phylib: fix potential use-after-free(CVE-2022-48754)

    ppdev: Add an error check in register_device(CVE-2024-36015)

    rtnetlink: make sure to refresh master_dev/m_ops in __rtnl_newlink()(CVE-2022-48742)

    scsi: qedf: Fix refcount issue when LOGO is received during TMF(CVE-2022-48823)

    scsi: qedi: Fix crash while reading debugfs attribute(CVE-2024-40978)

    tipc: fix a possible memleak in tipc_buf_append(CVE-2024-36954)

    tipc: fix kernel panic when enabling bearer(CVE-2022-48865)

    tipc: fix UAF in error path(CVE-2024-36886)

    virtio-blk: fix implicit overflow on virtio_max_dma_size(CVE-2023-52762)

    vmci: prevent speculation leaks by sanitizing event in event_deliver()(CVE-2024-39499)

    vsock: remove vsock from connected table when connect is interrupted by a signal(CVE-2022-48786)

    x86/mm/pat: fix VM_PAT handling in COW mappings(CVE-2024-35877)

    scsi: qedf: Add stag_work to all the vports(CVE-2022-48825)

    xprtrdma: fix pointer derefs in error cases of rpcrdma_ep_create(CVE-2022-48773)

    crypto: virtio/akcipher - Fix stack overflow on memcpy(CVE-2024-26753)

    bpf: Fix overrunning reservations in ringbuf(CVE-2024-41009)

    SUNRPC: lock against -sock changing during sysfs read(CVE-2022-48816)

    dmaengine: idxd: Fix possible Use-After-Free in irq_process_work_list(CVE-2024-40956)

    swiotlb: fix info leak with DMA_FROM_DEVICE(CVE-2022-48853)

    net: usb: ax88179_178a: Fix out-of-bounds accesses in RX fixup(CVE-2022-48805)

    cachefiles: flush all requests after setting CACHEFILES_DEAD(CVE-2024-40935)

    tracing/osnoise: Do not unregister events twice(CVE-2022-48848)

    drop_monitor: replace spin_lock by raw_spin_lock(CVE-2024-40980)

    tipc: force a dst refcount before doing decryption(CVE-2024-40983)

    RDMA/mlx5: Add check for srq max_sge attribute(CVE-2024-40990)

    md/raid5: fix deadlock that raid5d() wait for itself to clear MD_SB_CHANGE_PENDING(CVE-2024-39476)

    io_uring/io-wq: Use set_bit() and test_bit() at worker-flags(CVE-2024-39508)

    cachefiles: defer exposing anon_fd until after copy_to_user() succeeds(CVE-2024-40913)

    ext4: do not create EA inode under buffer lock(CVE-2024-40972)

    scsi: hisi_sas: Fix a deadlock issue related to automatic dump(CVE-2024-26873)

    cachefiles: fix slab-use-after-free in cachefiles_ondemand_get_fd()(CVE-2024-40899)

    null_blk: fix null-ptr-dereference while configuring 'power' and 'submit_queues'(CVE-2024-36478)

    md: fix resync softlockup when bitmap size is less than array size(CVE-2024-38598)

    cachefiles: fix slab-use-after-free in cachefiles_ondemand_daemon_read()(CVE-2024-39510)

    net: hns3: fix out-of-bounds access may occur when coalesce info is read via debugfs(CVE-2023-52807)

    HID: logitech-dj: Fix memory leak in logi_dj_recv_switch_to_dj_mode()(CVE-2024-40934)

    ring-buffer: Do not attempt to read past 'commit'(CVE-2023-52501)

    netfilter: ipset: Fix race between namespace cleanup and gc in the list:set type(CVE-2024-39503)

    drm/prime: Fix use after free in mmap with drm_gem_ttm_mmap(CVE-2021-47200)

    ipv6: fix possible race in __fib6_drop_pcpu_from()(CVE-2024-40905)

    bpf: Use VM_MAP instead of VM_ALLOC for ringbuf(CVE-2022-48714)

    sock_map: avoid race between sock_map_close and sk_psock_put(CVE-2024-39500)

    cpufreq: exit() callback is optional(CVE-2024-38615)

    bnxt_re: avoid shift undefined behavior in bnxt_qplib_alloc_init_hwq(CVE-2024-38540)

    xfs: fix log recovery buffer allocation for the legacy h_size fixup(CVE-2024-39472)

    USB: core: Make do_proc_control() and do_proc_bulk() killable(CVE-2021-47582)

    KVM: LAPIC: Also cancel preemption timer during SET_LAPIC(CVE-2022-48765)

    dma-mapping: benchmark: fix node id validation(CVE-2024-34777)

    net/mlx5e: Fix handling of wrong devices during bond netevent(CVE-2022-48746)

    ASoC: ops: Reject out of bounds values in snd_soc_put_volsw()(CVE-2022-48738)

    IB/hfi1: Fix AIP early init panic(CVE-2022-48728)

    usb-storage: alauda: Check whether the media is initialized(CVE-2024-38619)

    net/mlx5: Use del_timer_sync in fw reset flow of halting poll(CVE-2022-48745)

    tls: fix missing memory barrier in tls_init(CVE-2024-36489)

    efi: runtime: avoid EFIv2 runtime services on Apple x86 machines(CVE-2022-48769)

    net/mlx5e: Fix netif state handling(CVE-2024-38608)

    net: sched: fix possible refcount leak in tc_new_tfilter()(CVE-2022-48639)

    RDMA/rxe: Fix seg fault in rxe_comp_queue_pkt(CVE-2024-38544)

    usb: config: fix iteration issue in 'usb_get_bos_descriptor()'(CVE-2023-52781)

    ASoC: max9759: fix underflow in speaker_gain_control_put()(CVE-2022-48717)

    blk-mq: cancel blk-mq dispatch work in both blk_cleanup_queue and disk_release()(CVE-2021-47552)

    blk-mq: cancel blk-mq dispatch work in both blk_cleanup_queue and disk_release()(CVE-2024-26917)

    drm/vmwgfx: Fix stale file descriptors on failed usercopy(CVE-2022-48771)

    netfilter: bridge: replace physindev with physinif in nf_bridge_info(CVE-2024-35839)

    netfilter: bridge: replace physindev with physinif in nf_bridge_info(CVE-2021-47432)

    ceph: properly put ceph_string reference after async create attempt(CVE-2022-48767)

    hid: cp2112: Fix duplicate workqueue initialization(CVE-2023-52853)

    ALSA: hda: Do not unset preset when cleaning up codec(CVE-2023-52736)

    usb: xhci-plat: fix crash when suspend if remote wake enable(CVE-2022-48761)

    IB/IPoIB: Fix legacy IPoIB due to wrong number of queues(CVE-2023-52745)

    bpf, sockmap: Don't let sock_map_{close,destroy,unhash} call itself(CVE-2023-52735)

    bonding: stop the device in bond_setup_by_slave()(CVE-2023-52784)

    netfilter: nf_tables: flush pending destroy work before exit_net release(CVE-2024-35899)

    netfilter: nf_tables: honor table dormant flag from netdev release event path(CVE-2024-36005)

    ice: Fix crash by keep old cfg when update TCs more than queues(CVE-2022-48652)

    netfilter: ipset: fix performance regression in swap operation(CVE-2024-26910)

    dma-mapping: benchmark: handle NUMA_NO_NODE correctly(CVE-2024-39277)

    bpf: Add BPF_PROG_TYPE_CGROUP_SKB attach type enforcement in BPF_LINK_CREATE(CVE-2024-38564)

    vfio/pci: fix potential memory leak in vfio_intx_enable()(CVE-2024-38632)

    bpf: Allow delete from sockmap/sockhash only if update is allowed(CVE-2024-38662)

    bpf: Guard against accessing NULL pt_regs in bpf_get_task_stack()(CVE-2022-48770)

    perf/x86/intel/pt: Fix crash with stop filters in single-range mode(CVE-2022-48713)

    net/mlx5: Add a timeout to acquire the command queue semaphore(CVE-2024-38556)

    rcu-tasks: Fix show_rcu_tasks_trace_gp_kthread buffer overflow(CVE-2024-38577)

    net/mlx5: Discard command completions in internal error(CVE-2024-38555)

    powerpc64/bpf: Limit 'ldbrx' to processors compliant with ISA v2.06(CVE-2022-48755)

    tracing/histogram: Fix a potential memory leak for kstrdup()(CVE-2022-48768)

    fs/9p: fix uninitialized values during inode evict(CVE-2024-36923)

    net/mlx5e: Fix use-after-free of encap entry in neigh update handler(CVE-2021-47247)

    dmaengine: idxd: Fix oops during rmmod on single-CPU platforms(CVE-2024-35989)

    ipv4: Fix uninit-value access in __ip_make_skb()(CVE-2024-36927)

    netfilter: nft_set_pipapo: walk over current view on netlink dump(CVE-2024-27017)

    net: sched: sch_multiq: fix possible OOB write in multiq_tune()(CVE-2024-36978)

    misc/libmasm/module: Fix two use after free in ibmasm_init_one(CVE-2021-47334)

    locking/ww_mutex/test: Fix potential workqueue corruption(CVE-2023-52836)

    scsi: core: Fix unremoved procfs host directory regression(CVE-2024-26935)

    netfilter: nf_tables: do not compare internal table flags on updates(CVE-2024-27065)

    netfilter: nfnetlink_osf: fix possible bogus match in nf_osf_find()(CVE-2022-48654)

    of: fdt: fix off-by-one error in unflatten_dt_nodes()(CVE-2022-48672)

    nvme-tcp: fix UAF when detecting digest errors(CVE-2022-48686)

    pipe: wakeup wr_wait after setting max_usage(CVE-2023-52672)

    swiotlb: fix out-of-bounds TLB allocations with CONFIG_SWIOTLB_DYNAMIC(CVE-2023-52790)

    net: esp: fix bad handling of pages from page_pool(CVE-2024-26953)

    usb: typec: altmodes/displayport: create sysfs nodes as driver's default device attribute
    group(CVE-2024-35790)

    blk-iocost: do not WARN if iocg was already offlined(CVE-2024-36908)

    gpiolib: cdev: fix uninitialised kfifo(CVE-2024-36898)

    pinctrl: devicetree: fix refcount leak in pinctrl_dt_to_map()(CVE-2024-36959)

    mlxsw: spectrum_acl_tcam: Fix memory leak when canceling rehash work(CVE-2024-35852)

    KVM: arm64: vgic-v2: Check for non-NULL vCPU in vgic_v2_parse_attr()(CVE-2024-36953)

    mlxsw: spectrum_acl_tcam: Fix possible use-after-free during rehash(CVE-2024-35854)

    keys: Fix overwrite of key expiration on instantiation(CVE-2024-36031)

    net: hns3: fix kernel crash when devlink reload during pf initialization(CVE-2024-36021)

    fs/9p: only translate RWX permissions for plain 9P2000(CVE-2024-36964)

    ice: Do not use WQ_MEM_RECLAIM flag for workqueue(CVE-2023-52743)

    smb: client: fix potential deadlock when releasing mids(CVE-2023-52757)

    nfs: Handle error of rpc_proc_register() in nfs_net_init().(CVE-2024-36939)

    gpiolib: cdev: Fix use after free in lineinfo_changed_notify(CVE-2024-36899)

    blk-iocost: avoid out of bounds shift(CVE-2024-36916)

    bpf: Protect against int overflow for stack access size(CVE-2024-35905)

    smb: client: fix UAF in smb2_reconnect_server()(CVE-2024-35870)

    usb: typec: ucsi: Limit read size on v1.2(CVE-2024-35924)

    i40e: fix vf may be used uninitialized in this function warning(CVE-2024-36020)

    In the Linux kernel, the following vulnerability has been resolved: net: hns3: fix kernel crash when
    devlink reload during initialization The devlink reload process will access the hardware resources, but
    the register operation is done before the hardware is initialized. So, processing the devlink reload
    during initialization may lead to kernel crash. This patch fixes this by registering the devlink after
    hardware initialization. The Linux kernel CVE team has assigned CVE-2024-36900 to this
    issue.(CVE-2024-36900)

    net: ena: Fix incorrect descriptor free behavior(CVE-2024-35958)

    perf: hisi: Fix use-after-free when register pmu fails(CVE-2023-52859)

    mm/hugetlb: fix missing hugetlb_lock for resv uncharge(CVE-2024-36000)

    dma-direct: Leak pages on dma_set_decrypted() failure(CVE-2024-35939)

    netfilter: bridge: confirm multicast packets before passing them up the stack(CVE-2024-27415)

    netfilter: nf_tables: reject new basechain after table flag update(CVE-2024-35900)

    ceph: blocklist the kclient when receiving corrupted snap trace(CVE-2023-52732)

    geneve: fix header validation in geneve[6]_xmit_skb(CVE-2024-35973)

    of: dynamic: Synchronize of_changeset_destroy() with the devlink removals(CVE-2024-35879)

    netfilter: nft_flow_offload: reset dst in route object after setting up flow(CVE-2024-27403)

    netfilter: nf_tables: discard table flag update with pending basechain deletion(CVE-2024-35897)

    netfilter: nf_tables: use timestamp to check for set element timeout(CVE-2024-27397)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2519
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?260d4ced");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40956");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/09");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(12)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-5.10.0-136.12.0.86.h2059.eulerosv2r12",
  "kernel-5.10.0-136.12.0.86.h2059.eulerosv2r12",
  "kernel-abi-stablelists-5.10.0-136.12.0.86.h2059.eulerosv2r12",
  "kernel-tools-5.10.0-136.12.0.86.h2059.eulerosv2r12",
  "kernel-tools-libs-5.10.0-136.12.0.86.h2059.eulerosv2r12",
  "python3-perf-5.10.0-136.12.0.86.h2059.eulerosv2r12"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"12", reference:pkg)) flag++;

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
