#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212625);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2022-48748",
    "CVE-2022-48757",
    "CVE-2022-48867",
    "CVE-2022-48887",
    "CVE-2022-48939",
    "CVE-2022-49006",
    "CVE-2023-6356",
    "CVE-2023-6535",
    "CVE-2023-52664",
    "CVE-2023-52880",
    "CVE-2023-52889",
    "CVE-2023-52917",
    "CVE-2024-26820",
    "CVE-2024-26852",
    "CVE-2024-27414",
    "CVE-2024-33621",
    "CVE-2024-35898",
    "CVE-2024-35976",
    "CVE-2024-36017",
    "CVE-2024-36484",
    "CVE-2024-36929",
    "CVE-2024-39507",
    "CVE-2024-40945",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40961",
    "CVE-2024-40999",
    "CVE-2024-42286",
    "CVE-2024-42287",
    "CVE-2024-42288",
    "CVE-2024-42292",
    "CVE-2024-42301",
    "CVE-2024-42312",
    "CVE-2024-43819",
    "CVE-2024-43829",
    "CVE-2024-43834",
    "CVE-2024-43835",
    "CVE-2024-43845",
    "CVE-2024-43854",
    "CVE-2024-43855",
    "CVE-2024-43856",
    "CVE-2024-43863",
    "CVE-2024-43871",
    "CVE-2024-43872",
    "CVE-2024-43880",
    "CVE-2024-43889",
    "CVE-2024-43890",
    "CVE-2024-43892",
    "CVE-2024-43893",
    "CVE-2024-43894",
    "CVE-2024-43900",
    "CVE-2024-43914",
    "CVE-2024-44931",
    "CVE-2024-44934",
    "CVE-2024-44935",
    "CVE-2024-44944",
    "CVE-2024-44948",
    "CVE-2024-44952",
    "CVE-2024-44958",
    "CVE-2024-44986",
    "CVE-2024-44987",
    "CVE-2024-44989",
    "CVE-2024-44990",
    "CVE-2024-44995",
    "CVE-2024-45003",
    "CVE-2024-45006",
    "CVE-2024-45008",
    "CVE-2024-45016",
    "CVE-2024-45018",
    "CVE-2024-45021",
    "CVE-2024-45025",
    "CVE-2024-46673",
    "CVE-2024-46678",
    "CVE-2024-46679",
    "CVE-2024-46681",
    "CVE-2024-46695",
    "CVE-2024-46702",
    "CVE-2024-46707",
    "CVE-2024-46713",
    "CVE-2024-46715",
    "CVE-2024-46719",
    "CVE-2024-46721",
    "CVE-2024-46732",
    "CVE-2024-46733",
    "CVE-2024-46737",
    "CVE-2024-46738",
    "CVE-2024-46739",
    "CVE-2024-46743",
    "CVE-2024-46744",
    "CVE-2024-46750",
    "CVE-2024-46770",
    "CVE-2024-46777",
    "CVE-2024-46783",
    "CVE-2024-46787",
    "CVE-2024-46800",
    "CVE-2024-46813",
    "CVE-2024-46814",
    "CVE-2024-46815",
    "CVE-2024-46816",
    "CVE-2024-46822",
    "CVE-2024-46826",
    "CVE-2024-46829",
    "CVE-2024-46833",
    "CVE-2024-46834",
    "CVE-2024-46848",
    "CVE-2024-46855",
    "CVE-2024-46857",
    "CVE-2024-46859",
    "CVE-2024-47660",
    "CVE-2024-47671",
    "CVE-2024-47706"
  );

  script_name(english:"EulerOS 2.0 SP12 : kernel (EulerOS-SA-2024-2953)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    In the Linux kernel, the following vulnerability has been resolved:ntb: intel: Fix the NULL vs IS_ERR()
    bug for debugfs_create_dir()  The debugfs_create_dir() function returns error pointers. It never returns
    NULL. So use IS_ERR() to check it.(CVE-2023-52917)

    tracing: Free buffers when a used dynamic event is removed(CVE-2022-49006)

    block, bfq: fix possible UAF for bfqq-bic with merge chain(CVE-2024-47706)

    In the Linux kernel, the following vulnerability has been resolved:iommu: Return right value in
    iommu_sva_bind_device()  iommu_sva_bind_device() should return either a sva bond handle or an ERR_PTR
    value in error cases. Existing drivers (idxd and uacce) only check the return value with IS_ERR(). This
    could potentially lead to a kernel NULL pointer dereference issue if the function returns NULL instead of
    an error pointer.  In reality, this doesn't cause any problems because iommu_sva_bind_device() only
    returns NULL when the kernel is not configured with CONFIG_IOMMU_SVA. In this case,
    iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA) will return an error, and the device drivers won't call
    iommu_sva_bind_device() at all.(CVE-2024-40945)

    net: hns3: void array out of bound when loop tnl_num(CVE-2024-46833)

    KVM: arm64: Make ICC_*SGI*_EL1 undef in the absence of a vGICv3(CVE-2024-46707)

    net/mlx5: Fix bridge mode operations when there are no VFs(CVE-2024-46857)

    In the Linux kernel, the following vulnerability has been resolved:netfilter: nft_socket: fix sk refcount
    leaks  We must put 'sk' reference before returning.(CVE-2024-46855)

    fsnotify: clear PARENT_WATCHED flags lazily(CVE-2024-47660)

    tcp_bpf: fix return value of tcp_bpf_sendmsg()(CVE-2024-46783)

    mlxsw: spectrum_acl_erp: Fix object nesting warning(CVE-2024-43880)

    xdp: fix invalid wait context of page_pool_destroy()(CVE-2024-43834)

    virtio_net: Fix napi_skb_cache_put warning (CVE-2024-43835)

    net: hns3: fix kernel crash problem in concurrent scenario (CVE-2024-39507)

    xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr()(CVE-2024-40959)

    In the Linux kernel, the following vulnerability has been resolved:net: ena: Add validation for completion
    descriptors consistency  Validate that `first` flag is set only for the first descriptor in multi-buffer
    packets. In case of an invalid descriptor, a reset will occur. A new reset reason for RX data corruption
    has been added.(CVE-2024-40999)

    ipvlan: Dont Use skb-sk in ipvlan_process_v{4,6}_outbound(CVE-2024-33621)

    net: relax socket state check at accept time(CVE-2024-36484)

    net: fix information leakage in /proc/ net/ptype(CVE-2022-48757)

    net: bridge: vlan: fix memory leak in __allowed_ingress(CVE-2022-48748)

    In the Linux kernel, the following vulnerability has been resolved:USB: usbtmc: prevent kernel-usb-
    infoleak  The syzbot reported a kernel-usb-infoleak in usbtmc_write, we need to clear the structure before
    filling fields.(CVE-2024-47671)

    hv_netvsc: Register VF in netvsc_probe(CVE-2024-26820)

    vfs: Don't evict inode under the inode lru traversing context(CVE-2024-45003)

    perf/x86/intel: Limit the period on Haswell(CVE-2024-46848)

    ethtool: fail closed if we can't get max channel used in indirection tables(CVE-2024-46834)

    ELF: fix kernel.randomize_va_space double read(CVE-2024-46826)

    arm64: acpi: Harden get_cpu_for_acpi_id() against missing CPU entry(CVE-2024-46822)

    sched/smt: Fix unbalance sched_smt_present dec/inc(CVE-2024-44958)

    platform/x86: panasonic-laptop: Fix SINF array out of bounds accesses(CVE-2024-46859)

    rtmutex: Drop rt_mutex::wait_lock before scheduling(CVE-2024-46829)

    drm/amd/display: Check num_valid_sets before accessing reader_wm_sets[](CVE-2024-46815)

    drm/amd/display: Check link_index before accessing dc-links[](CVE-2024-46813)

    drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links(CVE-2024-46816)

    drm/amd/display: Check msg_id before processing transcation(CVE-2024-46814)

    thunderbolt: Mark XDomain as unplugged when router is removed(CVE-2024-46702)

    nvmet-tcp: fix kernel crash if commands allocation fails(CVE-2024-46737)

    of/irq: Prevent device address out-of-bounds read in interrupt map walk(CVE-2024-46743)

    VMCI: Fix use-after-free when removing resource in vmci_resource_remove()(CVE-2024-46738)

    usb: typec: ucsi: Fix null pointer dereference in trace(CVE-2024-46719)

    pktgen: use cpus_read_lock() in pg_net_init()(CVE-2024-46681)

    ethtool: check device is present when getting link settings(CVE-2024-46679)

    apparmor: fix possible NULL pointer dereference(CVE-2024-46721)

    selinux,smack: don't bypass permissions check in inode_setsecctx hook(CVE-2024-46695)

    bonding: change ipsec_lock from spin lock to mutex(CVE-2024-46678)

    PCI: Add missing bridge lock to pci_bus_lock()(CVE-2024-46750)

    ice: Add netif_device_attach/detach into PF reset flow(CVE-2024-46770)

    md: fix deadlock between mddev_suspend and flush bio(CVE-2024-43855)

    driver: iio: add missing checks on iio_info's callback access(CVE-2024-46715)

    uio_hv_generic: Fix kernel NULL pointer dereference in hv_uio_rescind (CVE-2024-46739)

    btrfs: fix qgroup reserve leaks in cow_file_range(CVE-2024-46733)

    Squashfs: sanity check symbolic link size(CVE-2024-46744)

    Input: MT - limit max slots(CVE-2024-45008)

    drm/amd/display: Assign linear_pitch_alignment even for VM(CVE-2024-46732)

    netem: fix return value if duplicate enqueue fails(CVE-2024-45016)

    sch/ netem: fix use after free in netem_dequeue(CVE-2024-46800)

    userfaultfd: fix checks for huge PMDs(CVE-2024-46787)

    netfilter: flowtable: initialise extack before use(CVE-2024-45018)

    rtnetlink: fix error logic of IFLA_BRIDGE_FLAGS writing back(CVE-2024-27414)

    xsk: validate user input for XDP_{UMEM|COMPLETION}_FILL_RING(CVE-2024-35976)

    net: atlantic: eliminate double free in error handling logic(CVE-2023-52664)

    netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get()(CVE-2024-35898)

    net/ipv6: avoid possible UAF in ip6_route_mpath_notify()(CVE-2024-26852)

    udf: Avoid excessive partition lengths(CVE-2024-46777)

    scsi: aacraid: Fix double-free on probe failure(CVE-2024-46673)

    In the Linux kernel, the following vulnerability has been resolved:memcg_write_event_control(): fix a
    user-triggerable oops  we are *not* guaranteed that anything past the terminating NUL is mapped (let alone
    initialized with anything sane).(CVE-2024-45021)

    drm/client: fix null pointer dereference in drm_client_modeset_probe(CVE-2024-43894)

    drm/qxl: Add check for drm_cvt_mode(CVE-2024-43829)

    rtnetlink: Correct nested IFLA_VF_VLAN_LIST attribute validation(CVE-2024-36017)

    net: core: reject skb_copy(_expand) for fraglist GSO skbs(CVE-2024-36929)

    perf/aux: Fix AUX buffer serialization(CVE-2024-46713)

    fix bitmap corruption on close_range() with CLOSE_RANGE_UNSHARE(CVE-2024-45025)

    driver core: Fix uevent_show() vs driver detach race(CVE-2024-44952)

    x86/mtrr: Check if fixed MTRRs exist before saving them(CVE-2024-44948)

    bonding: fix null pointer deref in bond_ipsec_offload_ok(CVE-2024-44990)

    net: hns3: fix a deadlock problem when config TC during resetting(CVE-2024-44995)

    bonding: fix xfrm real_dev null pointer dereference(CVE-2024-44989)

    scsi: qla2xxx: Fix for possible memory corruption(CVE-2024-42288)

    xhci: Fix Panther point NULL pointer deref at full-speed re-enumeration(CVE-2024-45006)

    dmaengine: idxd: Prevent use after free on completion memory(CVE-2022-48867)

    drm/vmwgfx: Remove rcu locks from user resources(CVE-2022-48887)

    RDMA/hns: Fix soft lockup under heavy CEQE load(CVE-2024-43872)

    ipv6: prevent UAF in ip6_send_skb()(CVE-2024-44987)

    md/raid5: avoid BUG_ON() while continue reshape after reassembling(CVE-2024-43914)

    kvm: s390: Reject memory region operations for ucontrol VMs(CVE-2024-43819)

    ipv6: fix possible UAF in ip6_finish_output2()(CVE-2024-44986)

    devres: Fix memory leakage caused by driver API devm_free_percpu()(CVE-2024-43871)

    drm/vmwgfx: Fix a deadlock in dma buf fence polling(CVE-2024-43863)

    media: xc2028: avoid use-after-free in load_firmware_cb()(CVE-2024-43900)

    gpio: prevent potential speculation leaks in gpio_device_get_desc()(CVE-2024-44931)

    netns: Make get_net_ns() handle zero refcount net(CVE-2024-40958)

    tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc(CVE-2023-52880)

    memcg: protect concurrent access to mem_cgroup_idr(CVE-2024-43892)

    netfilter: ctnetlink: use helper function to calculate expect ID(CVE-2024-44944)

    udf: Fix bogus checksum computation in udf_rename()(CVE-2024-43845)

    scsi: qla2xxx: validate nvme_local_port correctly(CVE-2024-42286)

    padata: Fix possible divide-by-0 panic in padata_mt_helper()(CVE-2024-43889)

    serial: core: check uartclk for zero to avoid divide by zero(CVE-2024-43893)

    sctp: Fix null-ptr-deref in reuseport_add_sock()(CVE-2024-44935)

    scsi: qla2xxx: Complete command early within lock(CVE-2024-42287)

    net: bridge: mcast: wait for previous gc cycles when removing port(CVE-2024-44934)

    bpf: Add schedule points in batch ops(CVE-2022-48939)

    apparmor: Fix null pointer deref when receiving skb during sock creation(CVE-2023-52889)

    dev/parport: fix the array out-of-bounds risk(CVE-2024-42301)

    block: initialize integrity buffer to zero before writing it to media(CVE-2024-43854)

    dma: fix call order in dmam_free_coherent(CVE-2024-43856)

    tracing: Fix overflow in get_free_elt()(CVE-2024-43890)

    ipv6: prevent possible NULL deref in fib6_nh_init()(CVE-2024-40961)

    sysctl: always initialize i_uid/i_gid(CVE-2024-42312)

    kobject_uevent: Fix OOB access within zap_modalias_env()(CVE-2024-42292)

    A flaw was found in the Linux kernel's NVMe driver. This issue may allow an unauthenticated malicious
    actor to send a set of crafted TCP packages when using NVMe over TCP, leading the NVMe driver to a NULL
    pointer dereference in the NVMe driver and causing kernel panic and a denial of service.(CVE-2023-6356)

    A flaw was found in the Linux kernel's NVMe driver. This issue may allow an unauthenticated malicious
    actor to send a set of crafted TCP packages when using NVMe over TCP, leading the NVMe driver to a NULL
    pointer dereference in the NVMe driver, causing kernel panic and a denial of service.(CVE-2023-6535)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2953
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54409eae");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-5.10.0-136.12.0.86.h2271.eulerosv2r12",
  "kernel-5.10.0-136.12.0.86.h2271.eulerosv2r12",
  "kernel-abi-stablelists-5.10.0-136.12.0.86.h2271.eulerosv2r12",
  "kernel-tools-5.10.0-136.12.0.86.h2271.eulerosv2r12",
  "kernel-tools-libs-5.10.0-136.12.0.86.h2271.eulerosv2r12",
  "python3-perf-5.10.0-136.12.0.86.h2271.eulerosv2r12"
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
