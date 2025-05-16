#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212605);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2022-48816",
    "CVE-2022-48867",
    "CVE-2022-48887",
    "CVE-2023-52653",
    "CVE-2023-52664",
    "CVE-2023-52791",
    "CVE-2023-52880",
    "CVE-2023-52889",
    "CVE-2023-52903",
    "CVE-2024-26921",
    "CVE-2024-33621",
    "CVE-2024-35898",
    "CVE-2024-35976",
    "CVE-2024-36017",
    "CVE-2024-36929",
    "CVE-2024-39507",
    "CVE-2024-40945",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40961",
    "CVE-2024-40999",
    "CVE-2024-41073",
    "CVE-2024-42067",
    "CVE-2024-42068",
    "CVE-2024-42265",
    "CVE-2024-42286",
    "CVE-2024-42288",
    "CVE-2024-42289",
    "CVE-2024-42292",
    "CVE-2024-42301",
    "CVE-2024-42312",
    "CVE-2024-43819",
    "CVE-2024-43829",
    "CVE-2024-43834",
    "CVE-2024-43835",
    "CVE-2024-43846",
    "CVE-2024-43853",
    "CVE-2024-43854",
    "CVE-2024-43855",
    "CVE-2024-43856",
    "CVE-2024-43863",
    "CVE-2024-43871",
    "CVE-2024-43880",
    "CVE-2024-43882",
    "CVE-2024-43889",
    "CVE-2024-43890",
    "CVE-2024-43892",
    "CVE-2024-43893",
    "CVE-2024-43894",
    "CVE-2024-43900",
    "CVE-2024-43914",
    "CVE-2024-44931",
    "CVE-2024-44935",
    "CVE-2024-44944",
    "CVE-2024-44947",
    "CVE-2024-44948",
    "CVE-2024-44986",
    "CVE-2024-44987",
    "CVE-2024-44989",
    "CVE-2024-44990",
    "CVE-2024-44995",
    "CVE-2024-45003",
    "CVE-2024-45006",
    "CVE-2024-45008",
    "CVE-2024-45016",
    "CVE-2024-45021",
    "CVE-2024-45025",
    "CVE-2024-46673",
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
    "CVE-2024-46834",
    "CVE-2024-46848",
    "CVE-2024-46857",
    "CVE-2024-46859",
    "CVE-2024-47660",
    "CVE-2024-47671",
    "CVE-2024-47685",
    "CVE-2024-47698",
    "CVE-2024-47706",
    "CVE-2024-49855",
    "CVE-2024-49860",
    "CVE-2024-49894",
    "CVE-2024-49996",
    "CVE-2024-50035",
    "CVE-2024-50036"
  );

  script_name(english:"EulerOS 2.0 SP11 : kernel (EulerOS-SA-2024-2983)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    kernel:SUNRPC: fix a memleak in gss_import_v2_context(CVE-2023-52653)

    apparmor: Fix null pointer deref when receiving skb during sock creation(CVE-2023-52889)

    protect the fetch of -fd[fd] in do_dup2() from mispredictions(CVE-2024-42265)

    tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc(CVE-2023-52880)

    padata: Fix possible divide-by-0 panic in padata_mt_helper()(CVE-2024-43889)

    dev/parport: fix the array out-of-bounds risk(CVE-2024-42301)

    netfilter: ctnetlink: use helper function to calculate expect ID(CVE-2024-44944)

    netns: Make get_net_ns() handle zero refcount net(CVE-2024-40958)

    ipv6: fix possible UAF in ip6_finish_output2()(CVE-2024-44986)

    kvm: s390: Reject memory region operations for ucontrol VMs(CVE-2024-43819)

    scsi: qla2xxx: validate nvme_local_port correctly(CVE-2024-42286)

    scsi: qla2xxx: During vport delete send async logout explicitly(CVE-2024-42289)

    gpio: prevent potential speculation leaks in gpio_device_get_desc()(CVE-2024-44931)

    ipv6: prevent possible NULL deref in fib6_nh_init()(CVE-2024-40961)

    cgroup/cpuset: Prevent UAF in proc_cpuset_show()(CVE-2024-43853)

    tracing: Fix overflow in get_free_elt()(CVE-2024-43890)

    exec: Fix ToCToU between perm check and set-uid/gid usage(CVE-2024-43882)

    drm/vmwgfx: Fix a deadlock in dma buf fence polling(CVE-2024-43863)

    io_uring: lock overflowing for IOPOLL(CVE-2023-52903)

    serial: core: check uartclk for zero to avoid divide by zero(CVE-2024-43893)

    sysctl: always initialize i_uid/i_gid(CVE-2024-42312)

    md/raid5: avoid BUG_ON() while continue reshape after reassembling(CVE-2024-43914)

    memcg: protect concurrent access to mem_cgroup_idr(CVE-2024-43892)

    scsi: qla2xxx: Fix for possible memory corruption(CVE-2024-42288)

    dmaengine: idxd: Prevent use after free on completion memory(CVE-2022-48867)

    x86/mtrr: Check if fixed MTRRs exist before saving them(CVE-2024-44948)

    dma: fix call order in dmam_free_coherent(CVE-2024-43856)

    block: initialize integrity buffer to zero before writing it to media(CVE-2024-43854)

    media: xc2028: avoid use-after-free in load_firmware_cb()(CVE-2024-43900)

    devres: Fix memory leakage caused by driver API devm_free_percpu()(CVE-2024-43871)

    lib: objagg: Fix general protection fault(CVE-2024-43846)

    xhci: Fix Panther point NULL pointer deref at full-speed re-enumeration(CVE-2024-45006)

    kobject_uevent: Fix OOB access within zap_modalias_env()(CVE-2024-42292)

    drm/client: fix null pointer dereference in drm_client_modeset_probe(CVE-2024-43894)

    drm/qxl: Add check for drm_cvt_mode(CVE-2024-43829)

    userfaultfd: fix checks for huge PMDs(CVE-2024-46787)

    md: fix deadlock between mddev_suspend and flush bio(CVE-2024-43855)

    udf: Avoid excessive partition lengths(CVE-2024-46777)

    uio_hv_generic: Fix kernel NULL pointer dereference in hv_uio_rescind (CVE-2024-46739)

    In the Linux kernel, the following vulnerability has been resolved:memcg_write_event_control(): fix a
    user-triggerable oops  we are *not* guaranteed that anything past the terminating NUL is mapped (let alone
    initialized with anything sane).(CVE-2024-45021)

    scsi: aacraid: Fix double-free on probe failure(CVE-2024-46673)

    Squashfs: sanity check symbolic link size(CVE-2024-46744)

    apparmor: fix possible NULL pointer dereference(CVE-2024-46721)

    of/irq: Prevent device address out-of-bounds read in interrupt map walk(CVE-2024-46743)

    PCI: Add missing bridge lock to pci_bus_lock()(CVE-2024-46750)

    fix bitmap corruption on close_range() with CLOSE_RANGE_UNSHARE(CVE-2024-45025)

    usb: typec: ucsi: Fix null pointer dereference in trace(CVE-2024-46719)

    thunderbolt: Mark XDomain as unplugged when router is removed(CVE-2024-46702)

    selinux,smack: don't bypass permissions check in inode_setsecctx hook(CVE-2024-46695)

    VMCI: Fix use-after-free when removing resource in vmci_resource_remove()(CVE-2024-46738)

    drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links(CVE-2024-46816)

    drm/amd/display: Check msg_id before processing transcation(CVE-2024-46814)

    sch/ netem: fix use after free in netem_dequeue(CVE-2024-46800)

    nvmet-tcp: fix kernel crash if commands allocation fails(CVE-2024-46737)

    drm/amd/display: Check num_valid_sets before accessing reader_wm_sets[](CVE-2024-46815)

    ice: Add netif_device_attach/detach into PF reset flow(CVE-2024-46770)

    driver: iio: add missing checks on iio_info's callback access(CVE-2024-46715)

    pktgen: use cpus_read_lock() in pg_net_init()(CVE-2024-46681)

    drm/amd/display: Check link_index before accessing dc-links[](CVE-2024-46813)

    drm/amd/display: Assign linear_pitch_alignment even for VM(CVE-2024-46732)

    rtmutex: Drop rt_mutex::wait_lock before scheduling(CVE-2024-46829)

    perf/aux: Fix AUX buffer serialization(CVE-2024-46713)

    Input: MT - limit max slots(CVE-2024-45008)

    SUNRPC: lock against -sock changing during sysfs read(CVE-2022-48816)

    inet: inet_defrag: prevent sk release while still in use(CVE-2024-26921)

    rtnetlink: Correct nested IFLA_VF_VLAN_LIST attribute validation(CVE-2024-36017)

    xsk: validate user input for XDP_{UMEM|COMPLETION}_FILL_RING(CVE-2024-35976)

    netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get()(CVE-2024-35898)

    net: atlantic: eliminate double free in error handling logic(CVE-2023-52664)

    In the Linux kernel, the following vulnerability has been resolved:USB: usbtmc: prevent kernel-usb-
    infoleak  The syzbot reported a kernel-usb-infoleak in usbtmc_write, we need to clear the structure before
    filling fields.(CVE-2024-47671)

    ELF: fix kernel.randomize_va_space double read(CVE-2024-46826)

    vfs: Don't evict inode under the inode lru traversing context(CVE-2024-45003)

    perf/x86/intel: Limit the period on Haswell(CVE-2024-46848)

    platform/x86: panasonic-laptop: Fix SINF array out of bounds accesses(CVE-2024-46859)

    arm64: acpi: Harden get_cpu_for_acpi_id() against missing CPU entry(CVE-2024-46822)

    ethtool: fail closed if we can't get max channel used in indirection tables(CVE-2024-46834)

    netem: fix return value if duplicate enqueue fails(CVE-2024-45016)

    ethtool: check device is present when getting link settings(CVE-2024-46679)

    In the Linux kernel, the following vulnerability has been resolved:iommu: Return right value in
    iommu_sva_bind_device()  iommu_sva_bind_device() should return either a sva bond handle or an ERR_PTR
    value in error cases. Existing drivers (idxd and uacce) only check the return value with IS_ERR(). This
    could potentially lead to a kernel NULL pointer dereference issue if the function returns NULL instead of
    an error pointer.  In reality, this doesn't cause any problems because iommu_sva_bind_device() only
    returns NULL when the kernel is not configured with CONFIG_IOMMU_SVA. In this case,
    iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA) will return an error, and the device drivers won't call
    iommu_sva_bind_device() at all.(CVE-2024-40945)

    xdp: fix invalid wait context of page_pool_destroy()(CVE-2024-43834)

    mlxsw: spectrum_acl_erp: Fix object nesting warning(CVE-2024-43880)

    virtio_net: Fix napi_skb_cache_put warning (CVE-2024-43835)

    tcp_bpf: fix return value of tcp_bpf_sendmsg()(CVE-2024-46783)

    drm/vmwgfx: Remove rcu locks from user resources(CVE-2022-48887)

    bonding: fix xfrm real_dev null pointer dereference(CVE-2024-44989)

    bonding: fix null pointer deref in bond_ipsec_offload_ok(CVE-2024-44990)

    net: core: reject skb_copy(_expand) for fraglist GSO skbs(CVE-2024-36929)

    block, bfq: fix possible UAF for bfqq-bic with merge chain(CVE-2024-47706)

    xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr()(CVE-2024-40959)

    ipvlan: Dont Use skb-sk in ipvlan_process_v{4,6}_outbound(CVE-2024-33621)

    In the Linux kernel, the following vulnerability has been resolved:net: ena: Add validation for completion
    descriptors consistency  Validate that `first` flag is set only for the first descriptor in multi-buffer
    packets. In case of an invalid descriptor, a reset will occur. A new reset reason for RX data corruption
    has been added.(CVE-2024-40999)

    net: hns3: fix kernel crash problem in concurrent scenario (CVE-2024-39507)

    net/mlx5: Fix bridge mode operations when there are no VFs(CVE-2024-46857)

    KVM: arm64: Make ICC_*SGI*_EL1 undef in the absence of a vGICv3(CVE-2024-46707)

    ipv6: prevent UAF in ip6_send_skb()(CVE-2024-44987)

    net: hns3: fix a deadlock problem when config TC during resetting(CVE-2024-44995)

    fsnotify: clear PARENT_WATCHED flags lazily(CVE-2024-47660)

    sctp: Fix null-ptr-deref in reuseport_add_sock()(CVE-2024-44935)

    bpf: Take return from set_memory_rox() into account with bpf_jit_binary_lock_ro()(CVE-2024-42067)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Take return from set_memory_ro()
    into account with bpf_prog_lock_ro() set_memory_ro() can fail, leaving memory unprotected. Check its
    return and take it into account as an error.(CVE-2024-42068)

    fuse: Initialize beyond-EOF page contents before setting uptodate(CVE-2024-44947)

    i2c: core: Run atomic i2c xfer when !preemptible(CVE-2023-52791)

    nvme: avoid double free special payload(CVE-2024-41073)

    drm/amd/display: Fix index out of bounds in degamma hardware format translation(CVE-2024-49894)

    drivers: media: dvb-frontends/rtl2832: fix an out-of-bounds write error(CVE-2024-47698)

    cifs: Fix buffer overflow when parsing NFS reparse points(CVE-2024-49996)

    netfilter: nf_reject_ipv6: fix nf_reject_ip6_tcphdr_put()(CVE-2024-47685)

    net: do not delay dst_entries_add() in dst_release()(CVE-2024-50036)

    ppp: fix ppp_async_encode() illegal access(CVE-2024-50035)

    ACPI: sysfs: validate return type of _STR method(CVE-2024-49860)

    nbd: fix race between timeout and normal completion(CVE-2024-49855)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2983
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a2f0d7e");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/13");
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
  "bpftool-5.10.0-60.18.0.50.h1674.eulerosv2r11",
  "kernel-5.10.0-60.18.0.50.h1674.eulerosv2r11",
  "kernel-abi-stablelists-5.10.0-60.18.0.50.h1674.eulerosv2r11",
  "kernel-tools-5.10.0-60.18.0.50.h1674.eulerosv2r11",
  "kernel-tools-libs-5.10.0-60.18.0.50.h1674.eulerosv2r11",
  "python3-perf-5.10.0-60.18.0.50.h1674.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
