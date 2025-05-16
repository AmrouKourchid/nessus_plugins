#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208398);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2021-47183",
    "CVE-2022-48652",
    "CVE-2022-48744",
    "CVE-2022-48828",
    "CVE-2023-52679",
    "CVE-2023-52754",
    "CVE-2023-52781",
    "CVE-2024-23848",
    "CVE-2024-24859",
    "CVE-2024-26846",
    "CVE-2024-26865",
    "CVE-2024-26878",
    "CVE-2024-26880",
    "CVE-2024-26881",
    "CVE-2024-26891",
    "CVE-2024-26910",
    "CVE-2024-27047",
    "CVE-2024-27062",
    "CVE-2024-27388",
    "CVE-2024-27417",
    "CVE-2024-35805",
    "CVE-2024-35839",
    "CVE-2024-35878",
    "CVE-2024-35884",
    "CVE-2024-35893",
    "CVE-2024-35899",
    "CVE-2024-35947",
    "CVE-2024-35965",
    "CVE-2024-35969",
    "CVE-2024-36005",
    "CVE-2024-36270",
    "CVE-2024-36286",
    "CVE-2024-37356",
    "CVE-2024-38538",
    "CVE-2024-38540",
    "CVE-2024-38541",
    "CVE-2024-38544",
    "CVE-2024-38552",
    "CVE-2024-38555",
    "CVE-2024-38556",
    "CVE-2024-38588",
    "CVE-2024-38590",
    "CVE-2024-38596",
    "CVE-2024-38598",
    "CVE-2024-38608",
    "CVE-2024-38659",
    "CVE-2024-39476",
    "CVE-2024-39480",
    "CVE-2024-39482",
    "CVE-2024-39487",
    "CVE-2024-39494",
    "CVE-2024-39497",
    "CVE-2024-39501",
    "CVE-2024-39509",
    "CVE-2024-40901",
    "CVE-2024-40905",
    "CVE-2024-40934",
    "CVE-2024-40953",
    "CVE-2024-40960",
    "CVE-2024-40966",
    "CVE-2024-40972",
    "CVE-2024-40980",
    "CVE-2024-40983",
    "CVE-2024-40995",
    "CVE-2024-41002",
    "CVE-2024-41005",
    "CVE-2024-41007",
    "CVE-2024-41012",
    "CVE-2024-41013",
    "CVE-2024-41014",
    "CVE-2024-41020",
    "CVE-2024-41023",
    "CVE-2024-41027",
    "CVE-2024-41035",
    "CVE-2024-41041",
    "CVE-2024-41042",
    "CVE-2024-41044",
    "CVE-2024-41048",
    "CVE-2024-41069",
    "CVE-2024-41079",
    "CVE-2024-41080",
    "CVE-2024-41082",
    "CVE-2024-41087",
    "CVE-2024-41089",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-41098",
    "CVE-2024-42070",
    "CVE-2024-42080",
    "CVE-2024-42082",
    "CVE-2024-42084",
    "CVE-2024-42090",
    "CVE-2024-42096",
    "CVE-2024-42098",
    "CVE-2024-42101",
    "CVE-2024-42106",
    "CVE-2024-42122",
    "CVE-2024-42131",
    "CVE-2024-42145",
    "CVE-2024-42148",
    "CVE-2024-42152",
    "CVE-2024-42154",
    "CVE-2024-42161",
    "CVE-2024-42223",
    "CVE-2024-42229",
    "CVE-2024-42232",
    "CVE-2024-42244",
    "CVE-2024-42246",
    "CVE-2024-42281",
    "CVE-2024-42283",
    "CVE-2024-42284",
    "CVE-2024-42285",
    "CVE-2024-42304",
    "CVE-2024-42321",
    "CVE-2024-42322",
    "CVE-2024-43828",
    "CVE-2024-43830",
    "CVE-2024-43861",
    "CVE-2024-43866"
  );

  script_name(english:"EulerOS 2.0 SP11 : kernel (EulerOS-SA-2024-2585)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    A race condition was found in the Linux kernel's net/bluetooth in sniff_{min,max}_interval_set() function.
    This can result in a bluetooth sniffing exception issue, possibly leading denial of
    service.(CVE-2024-24859)

    bnxt_re: avoid shift undefined behavior in bnxt_qplib_alloc_init_hwq(CVE-2024-38540)

    drivers: core: synchronize really_probe() and dev_uevent()(CVE-2024-39501)

    drm/amd/display: Fix potential index out of bounds in color transformation function(CVE-2024-38552)

    drop_monitor: replace spin_lock by raw_spin_lock(CVE-2024-40980)

    dyndbg: fix old BUG_ON in control parser(CVE-2024-35947)

    ext4: do not create EA inode under buffer lock(CVE-2024-40972)

    HID: logitech-dj: Fix memory leak in logi_dj_recv_switch_to_dj_mode()(CVE-2024-40934)

    ice: Fix crash by keep old cfg when update TCs more than queues(CVE-2022-48652)

    In the Linux kernel through 6.7.1, there is a use-after-free in cec_queue_msg_fh, related to
    drivers/media/cec/core/cec-adap.c and drivers/media/cec/core/cec-api.c.(CVE-2024-23848)

    ipv6: fix possible race in __fib6_drop_pcpu_from()(CVE-2024-40905)

    ipv6: fix potential 'struct net' leak in inet6_rtm_getaddr()(CVE-2024-27417)

    kernel:af_unix: Fix data races in unix_release_sock/unix_stream_sendmsg(CVE-2024-38596)

    kernel:bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set()(CVE-2024-39487)

    kernel:dm: call the resume method on internal suspend(CVE-2024-26880)

    kernel:fix lockup in dm_exception_table_exit  There was reported lockup(CVE-2024-35805)

    kernel:ftrace: Fix possible use-after-free issue in ftrace_location()(CVE-2024-38588)

    kernel:ima: Fix use-after-free on a dentry's dname.name(CVE-2024-39494)

    kernel:ipv6: fix race condition between ipv6_get_ifaddr and ipv6_del_addr(CVE-2024-35969)

    kernel:ipv6: prevent possible NULL dereference in rt6_probe()(CVE-2024-40960)

    kernel:kdb: Fix buffer overflow during tab-complete(CVE-2024-39480)

    kernel:net/mlx5e: Avoid field-overflowing memcpy()(CVE-2022-48744)

    kernel:net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc()(CVE-2024-40995)

    kernel:net: bridge: xmit: make sure we have at least eth header len bytes(CVE-2024-38538)

    kernel:netpoll: Fix race condition in netpoll_owner_active(CVE-2024-41005)

    kernel:nouveau: lock the client object tree. (CVE-2024-27062)

    kernel:nvme-fc: do not wait in vain when unloading module(CVE-2024-26846)

    kernel:of: Fix double free in of_parse_phandle_with_args_map(CVE-2023-52679)

    kernel:of: module: add buffer overflow check in of_modalias()(CVE-2024-38541)

    kernel:scsi: lpfc: Fix link down processing to address NULL pointer dereference(CVE-2021-47183)

    kernel:SUNRPC: fix some memleaks in gssx_dec_option_array(CVE-2024-27388)

    kernel:tcp: avoid too many retransmit packets(CVE-2024-41007)

    kernel:tcp: Fix shift-out-of-bounds in dctcp_update_alpha().(CVE-2024-37356)

    md/raid5: fix deadlock that raid5d() wait for itself to clear MD_SB_CHANGE_PENDING(CVE-2024-39476)

    md: fix resync softlockup when bitmap size is less than array size(CVE-2024-38598)

    media: imon: fix access to invalid resource for the second interface(CVE-2023-52754)

    net/mlx5: Add a timeout to acquire the command queue semaphore(CVE-2024-38556)

    net/mlx5: Discard command completions in internal error(CVE-2024-38555)

    net/mlx5e: Fix netif state handling(CVE-2024-38608)

    net/sched: act_skbmod: prevent kernel-infoleak(CVE-2024-35893)

    netfilter: bridge: replace physindev with physinif in nf_bridge_info(CVE-2024-35839)

    netfilter: ipset: fix performance regression in swap operation(CVE-2024-26910)

    netfilter: nf_tables: flush pending destroy work before exit_net release(CVE-2024-35899)

    netfilter: nf_tables: honor table dormant flag from netdev release event path(CVE-2024-36005)

    netfilter: nfnetlink_queue: acquire rcu_read_lock() in instance_destroy_rcu()(CVE-2024-36286)

    NFSD: Fix ia_size underflow(CVE-2022-48828)

    RDMA/rxe: Fix seg fault in rxe_comp_queue_pkt(CVE-2024-38544)

    scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory(CVE-2024-40901)

    tipc: force a dst refcount before doing decryption(CVE-2024-40983)

    usb: config: fix iteration issue in 'usb_get_bos_descriptor()'(CVE-2023-52781)

    bcache: fix variable length array abuse in btree_iter(CVE-2024-39482)

    pinctrl: fix deadlock in create_pinctrl() when handling -EPROBE_DEFER(CVE-2024-42090)

    udp: Set SOCK_RCU_FREE earlier in udp_lib_get_port().(CVE-2024-41041)

    net: hns3: fix kernel crash when 1588 is received on HIP08 devices(CVE-2024-26881)

    bpf: Fix a segment issue when downgrading gso_size(CVE-2024-42281)

    quota: Fix potential NULL pointer dereference(CVE-2024-26878)

    rds: tcp: Fix use-after-free of net in reqsk_timer_handler().(CVE-2024-26865)

    io_uring: fix possible deadlock in io_register_iowq_max_workers()(CVE-2024-41080)

    ASoC: topology: Fix references to freed memory(CVE-2024-41069)

    crypto: hisilicon/sec - Fix memory leak for sec resource release(CVE-2024-41002)

    filelock: Remove locks reliably when fcntl/close race is detected(CVE-2024-41012)

    x86: stop playing stack games in profile_pc()(CVE-2024-42096)

    iommu/vt-d: Don't issue ATS Invalidation request when device is disconnected(CVE-2024-26891)

    xfs: add bounds checking to xlog_recover_process_data(CVE-2024-41014)

    xfs: don't walk off the end of a directory data block(CVE-2024-41013)

    sched/deadline: Fix task_struct reference leak(CVE-2024-41023)

    of: module: prevent NULL pointer dereference in vsnprintf()(CVE-2024-35878)

    mm: avoid overflows in dirty throttling logic(CVE-2024-42131)

    drm/ nouveau: fix null pointer dereference in nouveau_connector_get_modes(CVE-2024-42101)

    crypto: ecdh - explicitly zeroize private_key(CVE-2024-42098)

    Fix userfaultfd_api to return EINVAL as expected(CVE-2024-41027)

    ftruncate: pass a signed offset(CVE-2024-42084)

    nvmet: fix a possible leak when destroy a ctrl during qp establishment(CVE-2024-42152)

    nvmet: always initialize cqe.result(CVE-2024-41079)

    crypto: aead,cipher - zeroize key buffer after use(CVE-2024-42229)

    Bluetooth: L2CAP: Fix not validating setsockopt user input(CVE-2024-35965)

    KVM: Fix a data race on last_boosted_vcpu in kvm_vcpu_on_spin()(CVE-2024-40953)

    filelock: Fix fcntl/close race recovery compat path(CVE-2024-41020)

    USB: serial: mos7840: fix crash on resume(CVE-2024-42244)

    tty: add the option to have a tty reject a new ldisc(CVE-2024-40966)

    media: dvb-frontends: tda10048: Fix integer overflow(CVE-2024-42223)

    ata: libata-core: Fix double free on error(CVE-2024-41087)

    ata: libata-core: Fix null pointer dereference on error(CVE-2024-41098)

    leds: trigger: Unregister sysfs attributes before calling deactivate()(CVE-2024-43830)

    enic: Validate length of nl attributes in enic_set_vf_port(CVE-2024-38659)

    tap: add missing verification for short frame(CVE-2024-41090)

    tun: add missing verification for short frame(CVE-2024-41091)

    netfilter: tproxy: bail out if IP has been disabled on the device(CVE-2024-36270)

    ext4: make sure the first directory block is not a hole(CVE-2024-42304)

    ext4: fix infinite loop when replaying fast_commit(CVE-2024-43828)

    ppp: reject claimed-as-LCP but actually malformed packets(CVE-2024-41044)

    RDMA/restrack: Fix potential invalid address access(CVE-2024-42080)

    nvme-fabrics: use reserved tag for reg read/write command(CVE-2024-41082)

    bnx2x: Fix multiple UBSAN array-index-out-of-bounds(CVE-2024-42148)

    inet_diag: Initialize pad field in struct inet_diag_req_v2(CVE-2024-42106)

    bpf: Avoid uninitialized value in BPF_CORE_READ_BITFIELD(CVE-2024-42161)

    drm/shmem-helper: Fix BUG_ON() on mmap(PROT_WRITE, MAP_PRIVATE)(CVE-2024-39497)

    drm/amd/display: Add NULL pointer check for kzalloc(CVE-2024-42122)

    net, sunrpc: Remap EPERM in case of connection failure in xs_tcp_setup_socket(CVE-2024-42246)

    net: phy: fix phy_get_internal_delay accessing an empty array(CVE-2024-27047)

    tcp_metrics: validate source addr length(CVE-2024-42154)

    netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers(CVE-2024-42070)

    RDMA/hns: Modify the print level of CQE error(CVE-2024-38590)

    udp: do not accept non-tunnel GSO skbs landing in a tunnel(CVE-2024-35884)

    skmsg: Skip zero length skb in sk_msg_recvmsg(CVE-2024-41048)

    xdp: Remove WARN() from __xdp_reg_mem_model()(CVE-2024-42082)

    HID: core: remove unnecessary WARN_ON() in implement()(CVE-2024-39509)

    net: nexthop: Initialize all fields in dumped nexthops(CVE-2024-42283)

    IB/core: Implement a limit on UMAD receive List(CVE-2024-42145)

    RDMA/iwcm: Fix a use-after-free related to destroying CM IDs(CVE-2024-42285)

    ipvs: properly dereference pe in ip_vs_add_service(CVE-2024-42322)

    net: usb: qmi_wwan: fix memory leak for not ip packets(CVE-2024-43861)

    libceph: fix race between delayed_work() and ceph_monc_stop()(CVE-2024-42232)

    tipc: Return non-zero value from tipc_udp_addr2str() on error(CVE-2024-42284)

    drm/ nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_hd_modes(CVE-2024-41089)

    netfilter: nf_tables: prefer nft_chain_validate(CVE-2024-41042)

    net: flow_dissector: use DEBUG_NET_WARN_ON_ONCE(CVE-2024-42321)

    net/mlx5: Always drain health in shutdown callback(CVE-2024-43866)

    USB: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor(CVE-2024-41035)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2585
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1166a06");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42285");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/23");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-5.10.0-60.18.0.50.h1587.eulerosv2r11",
  "kernel-5.10.0-60.18.0.50.h1587.eulerosv2r11",
  "kernel-abi-stablelists-5.10.0-60.18.0.50.h1587.eulerosv2r11",
  "kernel-tools-5.10.0-60.18.0.50.h1587.eulerosv2r11",
  "kernel-tools-libs-5.10.0-60.18.0.50.h1587.eulerosv2r11",
  "python3-perf-5.10.0-60.18.0.50.h1587.eulerosv2r11"
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
