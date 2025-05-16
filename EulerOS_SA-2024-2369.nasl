#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207170);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_cve_id(
    "CVE-2021-46952",
    "CVE-2021-47183",
    "CVE-2021-47184",
    "CVE-2021-47201",
    "CVE-2021-47236",
    "CVE-2021-47259",
    "CVE-2021-47261",
    "CVE-2021-47265",
    "CVE-2021-47277",
    "CVE-2021-47280",
    "CVE-2021-47293",
    "CVE-2021-47301",
    "CVE-2021-47311",
    "CVE-2021-47329",
    "CVE-2021-47353",
    "CVE-2021-47354",
    "CVE-2021-47373",
    "CVE-2021-47383",
    "CVE-2021-47397",
    "CVE-2021-47408",
    "CVE-2021-47416",
    "CVE-2021-47424",
    "CVE-2021-47425",
    "CVE-2021-47427",
    "CVE-2021-47435",
    "CVE-2021-47438",
    "CVE-2021-47455",
    "CVE-2021-47466",
    "CVE-2021-47469",
    "CVE-2021-47473",
    "CVE-2021-47478",
    "CVE-2021-47480",
    "CVE-2021-47483",
    "CVE-2021-47495",
    "CVE-2021-47497",
    "CVE-2021-47501",
    "CVE-2021-47516",
    "CVE-2021-47527",
    "CVE-2021-47541",
    "CVE-2021-47544",
    "CVE-2021-47548",
    "CVE-2021-47565",
    "CVE-2021-47566",
    "CVE-2021-47576",
    "CVE-2021-47579",
    "CVE-2021-47588",
    "CVE-2021-47589",
    "CVE-2021-47597",
    "CVE-2021-47606",
    "CVE-2021-47609",
    "CVE-2021-47619",
    "CVE-2022-48695",
    "CVE-2022-48715",
    "CVE-2022-48742",
    "CVE-2022-48744",
    "CVE-2022-48754",
    "CVE-2022-48786",
    "CVE-2022-48799",
    "CVE-2022-48804",
    "CVE-2022-48809",
    "CVE-2022-48810",
    "CVE-2022-48855",
    "CVE-2023-52478",
    "CVE-2023-52653",
    "CVE-2023-52679",
    "CVE-2023-52698",
    "CVE-2023-52703",
    "CVE-2023-52708",
    "CVE-2023-52739",
    "CVE-2023-52752",
    "CVE-2023-52796",
    "CVE-2023-52803",
    "CVE-2023-52813",
    "CVE-2023-52835",
    "CVE-2023-52843",
    "CVE-2023-52868",
    "CVE-2023-52881",
    "CVE-2024-26633",
    "CVE-2024-26641",
    "CVE-2024-26846",
    "CVE-2024-26880",
    "CVE-2024-26883",
    "CVE-2024-27020",
    "CVE-2024-27062",
    "CVE-2024-27388",
    "CVE-2024-35789",
    "CVE-2024-35805",
    "CVE-2024-35807",
    "CVE-2024-35808",
    "CVE-2024-35809",
    "CVE-2024-35815",
    "CVE-2024-35823",
    "CVE-2024-35835",
    "CVE-2024-35847",
    "CVE-2024-35886",
    "CVE-2024-35888",
    "CVE-2024-35896",
    "CVE-2024-35904",
    "CVE-2024-35910",
    "CVE-2024-35922",
    "CVE-2024-35925",
    "CVE-2024-35930",
    "CVE-2024-35955",
    "CVE-2024-35960",
    "CVE-2024-35962",
    "CVE-2024-35969",
    "CVE-2024-35984",
    "CVE-2024-35995",
    "CVE-2024-35997",
    "CVE-2024-36004",
    "CVE-2024-36016",
    "CVE-2024-36883",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36903",
    "CVE-2024-36904",
    "CVE-2024-36905",
    "CVE-2024-36917",
    "CVE-2024-36919",
    "CVE-2024-36924",
    "CVE-2024-36940",
    "CVE-2024-36952",
    "CVE-2024-36971",
    "CVE-2024-37353",
    "CVE-2024-37356",
    "CVE-2024-38538",
    "CVE-2024-38541",
    "CVE-2024-38559",
    "CVE-2024-38588",
    "CVE-2024-38596",
    "CVE-2024-38601",
    "CVE-2024-39276",
    "CVE-2024-39480",
    "CVE-2024-39487",
    "CVE-2024-40904",
    "CVE-2024-40960",
    "CVE-2024-40984",
    "CVE-2024-40995",
    "CVE-2024-40998",
    "CVE-2024-41005",
    "CVE-2024-41007"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"EulerOS 2.0 SP9 : kernel (EulerOS-SA-2024-2369)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    kernel:ACPI: CPPC: Use access_width over bit_width for system memory accesses(CVE-2024-35995)

    kernel: block: fix overflow in blk_ioctl_discard()(CVE-2024-36917)

    kernel:block: prevent division by zero in blk_rq_stat_sum()(CVE-2024-35925)

    bpf: Fix stackmap overflow check on 32-bit arches(CVE-2024-26883)

    kernel:calipso: fix memory leak in netlbl_calipso_add_pass()(CVE-2023-52698)

    kernel:erspan: make sure erspan_base_hdr is present in skb-head(CVE-2024-35888)

    kernel: ext4: fix corruption during on-line resize(CVE-2024-35807)

    kernel:HID: i2c-hid: remove I2C_HID_READ_PENDING flag to prevent lock-up(CVE-2024-35997)

    HID: logitech-hidpp: Fix kernel crash on receiver USB disconnect(CVE-2023-52478)

    kernel:i2c: smbus: fix NULL function pointer dereference(CVE-2024-35984)

    kernel:i40e: Do not use WQ_MEM_RECLAIM flag for workqueue(CVE-2024-36004)

    i40e: Fix NULL ptr dereference on VSI filter sync(CVE-2021-47184)

    iavf: free q_vectors before queues in iavf_disable_vf(CVE-2021-47201)

    ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim()(CVE-2024-26633)

    ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv()(CVE-2024-26641)

    kernel:ipv6: fib6_rules: avoid possible NULL dereference in fib6_rule_action()(CVE-2024-36902)

    kernel:ipv6: Fix infinite recursion in fib6_dump_done().(CVE-2024-35886)

    kernel:ipv6: Fix potential uninit-value access in __ip6_make_skb()(CVE-2024-36903)

    kernel:ipv6: prevent NULL dereference in ip6_output()(CVE-2024-36901)

    kernel:ipvlan: add ipvlan_route_v6_outbound() helper(CVE-2023-52796)

    kernel:irqchip/gic-v3-its: Prevent double free on error(CVE-2024-35847)

    kernel: md/dm-raid: don#39;t call md_reap_sync_thread() directly(CVE-2024-35808)

    kernel:net/mlx5: Properly link new fs rules into the tree(CVE-2024-35960)

    kernel:net/mlx5e: fix a double-free in arfs_create_groups(CVE-2024-35835)

    kernel:net: fix __dst_negative_advice() race(CVE-2024-36971)

    kernel:net: fix out-of-bounds access in ops_init(CVE-2024-36883)

    kernel:netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get()(CVE-2024-27020)

    kernel:netfilter: validate user input for expected length(CVE-2024-35896)

    NFS: fs_context: validate UDP retrans to prevent shift out-of-bounds(CVE-2021-46952)

    kernel:nvme-fc: do not wait in vain when unloading module(CVE-2024-26846)

    nvmem: Fix shift-out-of-bound (UBSAN) with byte size cells(CVE-2021-47497)

    kernel: PCI/PM: Drain runtime-idle callbacks before driver removal(CVE-2024-35809)

    kernel: perf/core: Bail out early if the request AUX area is out of bound(CVE-2023-52835)

    kernel: pinctrl: core: delete incorrect free in pinctrl_enable()(CVE-2024-36940)

    kernel:dm: call the resume method on internal suspend(CVE-2024-26880)

    kernel:RDMA: Verify port when creating flow rule(CVE-2021-47265)

    kernel:ring-buffer: Fix a race between readers and resize checks(CVE-2024-38601)

    kernel: scsi: bnx2fc: Remove spin_lock_bh while releasing resources after upload(CVE-2024-36919)

    kernel:scsi: iscsi: Fix iscsi_task use after free(CVE-2021-47427)

    kernel:scsi: lpfc: Fix link down processing to address NULL pointer dereference(CVE-2021-47183)

    kernel:scsi: lpfc: Release hbalock before calling lpfc_worker_wake_up()(CVE-2024-36924)

    kernel: scsi: mpt3sas: Fix use-after-free warning(CVE-2022-48695)

    kernel: selinux: avoid dereference of garbage after mount failure(CVE-2024-35904)

    kernel: smb: client: fix use-after-free bug in cifs_debug_data_proc_show()(CVE-2023-52752)

    kernel:spi: Fix deadlock when adding SPI controllers on SPI buses(CVE-2021-47469)

    kernel:SUNRPC: fix a memleak in gss_import_v2_context(CVE-2023-52653)

    kernel:tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets(CVE-2024-36905)

    kernel:tcp: properly terminate timers for kernel sockets(CVE-2024-35910)

    kernel:tcp: Use refcount_inc_not_zero() in tcp_twsk_unique().(CVE-2024-36904)

    kernel: thermal: core: prevent potential string overflow(CVE-2023-52868)

    tty: Fix out-of-bound vmalloc access in imageblit(CVE-2021-47383)

    kernel:tty: n_gsm: fix possible out-of-bounds in gsm0_receive()(CVE-2024-36016)

    kernel:vt: fix unicode buffer corruption when deleting characters(CVE-2024-35823)

    kernel:llc: verify mac len before reading mac header(CVE-2023-52843)

    kernel:SUNRPC: fix some memleaks in gssx_dec_option_array(CVE-2024-27388)

    kernel:net: cdc_eem: fix tx fixup skb leak(CVE-2021-47236)

    NFS: Fix use-after-free in nfs4_init_client()(CVE-2021-47259)

    kernel: IB/mlx5: Fix initializing CQ fragments buffer(CVE-2021-47261)

    kernel:kvm: avoid speculation-based attacks from out-of-range memslot accesses(CVE-2021-47277)

    kernel: drm: Fix use-after-free read in drm_getunique()(CVE-2021-47280)

    net/sched: act_skbmod: Skip non-Ethernet packets(CVE-2021-47293)

    kernel:igb: Fix use-after-free error during reset(CVE-2021-47301)

    kernel:net: qcom/emac: fix UAF in emac_remove(CVE-2021-47311)

    kernel:scsi: megaraid_sas: Fix resource leak in case of probe failure(CVE-2021-47329)

    kernel: udf: Fix NULL pointer dereference in udf_symlink function(CVE-2021-47353)

    kernel: drm/sched: Avoid data corruptions(CVE-2021-47354)

    irqchip/gic-v3-its: Fix potential VPE leak on error(CVE-2021-47373)

    kernel:sctp: break out if skb_header_pointer returns NULL in sctp_rcv_ootb(CVE-2021-47397)

    kernel: netfilter: conntrack: serialize hash resizes and cleanups(CVE-2021-47408)

    phy: mdio: fix memory leak(CVE-2021-47416)

    i40e: Fix freeing of uninitialized misc IRQ vector(CVE-2021-47424)

    kernel:i2c: acpi: fix resource leak in reconfiguration device addition(CVE-2021-47425)

    kernel: dm: fix mempool NULL pointer race when completing IO(CVE-2021-47435)

    kernel:net/mlx5e: Fix memory leak in mlx5_core_destroy_cq() error path(CVE-2021-47438)

    kernel:ptp: Fix possible memory leak in ptp_clock_register()(CVE-2021-47455)

    kernel: mm, slub: fix potential memoryleak in kmem_cache_open()(CVE-2021-47466)

    kernel: scsi: qla2xxx: Fix a memory leak in an error path of qla2x00_process_els()(CVE-2021-47473)

    kernel: isofs: Fix out of bound access for corrupted isofs image(CVE-2021-47478)

    kernel: scsi: core: Put LLD module refcnt after SCSI device is released(CVE-2021-47480)

    kernel:regmap: Fix possible double-free in regcache_rbtree_exit()(CVE-2021-47483)

    kernel:usbnet: sanity check for maxpacket(CVE-2021-47495)

    kernel:i40e: Fix NULL pointer dereference in i40e_dbg_dump_desc(CVE-2021-47501)

    kernel:nfp: Fix memory leak in nfp_cpp_area_cache_add()(CVE-2021-47516)

    serial: core: fix transmit-buffer reset and memleak(CVE-2021-47527)

    kernel:net/mlx4_en: Fix an use-after-free bug in mlx4_en_try_alloc_resources()(CVE-2021-47541)

    tcp: fix page frag corruption on page fault(CVE-2021-47544)

    kernel:ethernet: hisilicon: hns: hns_dsaf_misc: fix a possible array overflow in
    hns_dsaf_ge_srst_by_port()(CVE-2021-47548)

    kernel: scsi: mpt3sas: Fix kernel panic during drive powercycle test(CVE-2021-47565)

    proc/vmcore: fix clearing user buffer by properly using clear_user()(CVE-2021-47566)

    scsi: scsi_debug: Sanity check block descriptor length in resp_mode_select()(CVE-2021-47576)

    ovl: fix warning in ovl_create_real()(CVE-2021-47579)

    sit: do not call ipip6_dev_free() from sit_init_net()(CVE-2021-47588)

    igbvf: fix double free in `igbvf_probe`(CVE-2021-47589)

    kernel:inet_diag: fix kernel-infoleak for UDP sockets(CVE-2021-47597)

    net: netlink: af_netlink: Prevent empty skb by adding a check on len.(CVE-2021-47606)

    kernel:firmware: arm_scpi: Fix string overflow in SCPI genpd driver(CVE-2021-47609)

    kernel:i40e: Fix queues reservation for XDP(CVE-2021-47619)

    kernel: scsi: bnx2fc: Make bnx2fc_recv_frame() mp safe(CVE-2022-48715)

    rtnetlink: make sure to refresh master_dev/m_ops in __rtnl_newlink()(CVE-2022-48742)

    kernel:net/mlx5e: Avoid field-overflowing memcpy()(CVE-2022-48744)

    phylib: fix potential use-after-free(CVE-2022-48754)

    vsock: remove vsock from connected table when connect is interrupted by a signal(CVE-2022-48786)

    perf: Fix list corruption in perf_cgroup_switch()(CVE-2022-48799)

    kernel:vt_ioctl: fix array_index_nospec in vt_setactivate(CVE-2022-48804)

    net: fix a memleak when uncloning an skb dst and its metadata(CVE-2022-48809)

    ipmr,ip6mr: acquire RTNL before calling ip[6]mr_free_table() on failure path(CVE-2022-48810)

    kernel:sctp: fix kernel-infoleak for SCTP sockets(CVE-2022-48855)

    kernel:of: Fix double free in of_parse_phandle_with_args_map(CVE-2023-52679)

    kernel:net/usb: kalmia: Don't pass act_len in usb_bulk_msg error path(CVE-2023-52703)

    kernel: mmc: mmc_spi: fix error handling in mmc_spi_probe()(CVE-2023-52708)

    kernel: Fix page corruption caused by racy check in __free_pages(CVE-2023-52739)

    kernel:SUNRPC: Fix RPC client cleaned up the freed pipefs dentries(CVE-2023-52803)

    kernel: crypto: pcrypt - Fix hungtask for PADATA_RESET(CVE-2023-52813)

    kernel:tcp: do not accept ACK of bytes we never sent(CVE-2023-52881)

    kernel:nouveau: lock the client object tree. (CVE-2024-27062)

    kernel: wifi: mac80211: check/clear fast rx for non-4addr sta VLAN changes(CVE-2024-35789)

    kernel:fix lockup in dm_exception_table_exit  There was reported lockup(CVE-2024-35805)

    kernel: fs/aio: Check IOCB_AIO_RW before the struct aio_kiocb conversion(CVE-2024-35815)

    kernel: fbmon: prevent division by zero in fb_videomode_from_videomode()(CVE-2024-35922)

    kernel:scsi: lpfc: Fix possible memory leak in lpfc_rcv_padisc()  (CVE-2024-35930)

    kernel:kprobes: Fix possible use-after-free issue on kprobe registration(CVE-2024-35955)

    kernel:netfilter: complete validation of user input(CVE-2024-35962)

    kernel:ipv6: fix race condition between ipv6_get_ifaddr and ipv6_del_addr(CVE-2024-35969)

    kernel: scsi: lpfc: Move NPIV's transport unregistration to after resource clean up(CVE-2024-36952)

    kernel:virtio: delete vq in vp_find_vqs_msix() when request_irq() fails(CVE-2024-37353)

    kernel:tcp: Fix shift-out-of-bounds in dctcp_update_alpha().(CVE-2024-37356)

    kernel:net: bridge: xmit: make sure we have at least eth header len bytes(CVE-2024-38538)

    kernel:of: module: add buffer overflow check in of_modalias()(CVE-2024-38541)

    kernel:scsi: qedf: Ensure the copied buf is NUL terminated(CVE-2024-38559)

    kernel:ftrace: Fix possible use-after-free issue in ftrace_location()(CVE-2024-38588)

    kernel:af_unix: Fix data races in unix_release_sock/unix_stream_sendmsg(CVE-2024-38596)

    kernel: ext4: fix mb_cache_entry#39;s e_refcnt leak in ext4_xattr_block_cache_find()CVE-2024-39276)

    kernel:kdb: Fix buffer overflow during tab-complete(CVE-2024-39480)

    kernel:bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set()(CVE-2024-39487)

    kernel:USB: class: cdc-wdm: Fix CPU lockup caused by excessive log messages(CVE-2024-40904)

    kernel:ipv6: prevent possible NULL dereference in rt6_probe()(CVE-2024-40960)

    kernel:ACPICA: Revert 'ACPICA: avoid Info: mapping multiple BARs. Your kernel is fine.(CVE-2024-40984)

    kernel:net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc()(CVE-2024-40995)

    kernel:ext4: fix uninitialized ratelimit_state-lock access in __ext4_fill_super()(CVE-2024-40998)

    kernel:netpoll: Fix race condition in netpoll_owner_active(CVE-2024-41005)

    kernel:tcp: avoid too many retransmit packets(CVE-2024-41007)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2369
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b721551");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39480");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/08");
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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.19.90-vhulk2103.1.0.h1335.eulerosv2r9",
  "kernel-tools-4.19.90-vhulk2103.1.0.h1335.eulerosv2r9",
  "kernel-tools-libs-4.19.90-vhulk2103.1.0.h1335.eulerosv2r9",
  "python3-perf-4.19.90-vhulk2103.1.0.h1335.eulerosv2r9"
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
