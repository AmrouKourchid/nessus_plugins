#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210249);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2021-47391",
    "CVE-2022-48712",
    "CVE-2022-48724",
    "CVE-2022-48732",
    "CVE-2022-48789",
    "CVE-2022-48796",
    "CVE-2022-48834",
    "CVE-2022-48836",
    "CVE-2022-48850",
    "CVE-2023-52696",
    "CVE-2023-52742",
    "CVE-2024-23848",
    "CVE-2024-26881",
    "CVE-2024-26891",
    "CVE-2024-27047",
    "CVE-2024-35801",
    "CVE-2024-35878",
    "CVE-2024-35884",
    "CVE-2024-36270",
    "CVE-2024-36286",
    "CVE-2024-38659",
    "CVE-2024-39482",
    "CVE-2024-39494",
    "CVE-2024-39497",
    "CVE-2024-39501",
    "CVE-2024-40947",
    "CVE-2024-40953",
    "CVE-2024-41002",
    "CVE-2024-41012",
    "CVE-2024-41013",
    "CVE-2024-41014",
    "CVE-2024-41020",
    "CVE-2024-41023",
    "CVE-2024-41027",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41048",
    "CVE-2024-41049",
    "CVE-2024-41050",
    "CVE-2024-41051",
    "CVE-2024-41069",
    "CVE-2024-41074",
    "CVE-2024-41075",
    "CVE-2024-41077",
    "CVE-2024-41079",
    "CVE-2024-41080",
    "CVE-2024-41082",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-41095",
    "CVE-2024-41097",
    "CVE-2024-42067",
    "CVE-2024-42068",
    "CVE-2024-42070",
    "CVE-2024-42080",
    "CVE-2024-42082",
    "CVE-2024-42084",
    "CVE-2024-42090",
    "CVE-2024-42096",
    "CVE-2024-42098",
    "CVE-2024-42101",
    "CVE-2024-42106",
    "CVE-2024-42124",
    "CVE-2024-42131",
    "CVE-2024-42147",
    "CVE-2024-42148",
    "CVE-2024-42152",
    "CVE-2024-42154",
    "CVE-2024-42161",
    "CVE-2024-42223",
    "CVE-2024-42229",
    "CVE-2024-42246"
  );

  script_name(english:"EulerOS 2.0 SP12 : kernel (EulerOS-SA-2024-2806)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    ASoC: topology: Fix references to freed memory(CVE-2024-41069)

    bcache: fix variable length array abuse in btree_iter(CVE-2024-39482)

    bnx2x: Fix multiple UBSAN array-index-out-of-bounds(CVE-2024-42148)

    bpf: Avoid uninitialized value in BPF_CORE_READ_BITFIELD(CVE-2024-42161)

    bpf: Take return from set_memory_ro() into account with bpf_prog_lock_ro(CVE-2024-42068)

    bpf: Take return from set_memory_rox() into account with bpf_jit_binary_lock_ro(CVE-2024-42067)

    cachefiles: add consistency check for copen/cread(CVE-2024-41075)

    cachefiles: cyclic allocation of msg_id to avoid reuse(CVE-2024-41050)

    cachefiles: Set object to close if ondemand_id  0 in copen(CVE-2024-41074)

    cachefiles: wait for ondemand_object_worker to finish when dropping object(CVE-2024-41051)

    crypto: aead,cipher - zeroize key buffer after use(CVE-2024-42229)

    crypto: ecdh - explicitly zeroize private_key(CVE-2024-42098)

    crypto: hisilicon/debugfs - Fix debugfs uninit process issue(CVE-2024-42147)

    crypto: hisilicon/sec - Fix memory leak for sec resource release(CVE-2024-41002)

    drivers: core: synchronize really_probe() and dev_uevent(CVE-2024-39501)

    drm/ nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_ld_modes(CVE-2024-41095)

    drm/ nouveau: fix null pointer dereference in nouveau_connector_get_modes(CVE-2024-42101)

    drm/ nouveau: fix off by one in BIOS boundary checking(CVE-2022-48732)

    drm/shmem-helper: Fix BUG_ON() on mmap(PROT_WRITE, MAP_PRIVATE)(CVE-2024-39497)

    enic: Validate length of nl attributes in enic_set_vf_port(CVE-2024-38659)

    ext4: fix error handling in ext4_fc_record_modified_inode()(CVE-2022-48712)

    filelock: Fix fcntl/close race recovery compat path(CVE-2024-41020)

    filelock: fix potential use-after-free in posix_lock_inode(CVE-2024-41049)

    filelock: Remove locks reliably when fcntl/close race is detected(CVE-2024-41012)

    Fix userfaultfd_api to return EINVAL as expected(CVE-2024-41027)

    ftruncate: pass a signed offset(CVE-2024-42084)

    ima: Avoid blocking in RCU read-side critical section(CVE-2024-40947)

    In the Linux kernel through 6.7.1, there is a use-after-free in cec_queue_msg_fh, related to
    drivers/media/cec/core/cec-adap.c and drivers/media/cec/core/cec-api.c.(CVE-2024-23848)

    inet_diag: Initialize pad field in struct inet_diag_req_v2(CVE-2024-42106)

    Input: aiptek - properly check endpoint type(CVE-2022-48836)

    io_uring: fix possible deadlock in io_register_iowq_max_workers()(CVE-2024-41080)

    iommu/vt-d: Don't issue ATS Invalidation request when device is disconnected(CVE-2024-26891)

    iommu/vt-d: Fix potential memory leak in intel_setup_irq_remapping()(CVE-2022-48724)

    iommu: Fix potential use-after-free during probe(CVE-2022-48796)

    kernel:ima: Fix use-after-free on a dentry's dname.name(CVE-2024-39494)

    kernel:RDMA/cma: Ensure rdma_addr_cancel() happens before issuing more requests(CVE-2021-47391)

    KVM: Fix a data race on last_boosted_vcpu in kvm_vcpu_on_spin(CVE-2024-40953)

    media: dvb-frontends: tda10048: Fix integer overflow(CVE-2024-42223)

    mm: avoid overflows in dirty throttling logic(CVE-2024-42131)

    net, sunrpc: Remap EPERM in case of connection failure in xs_tcp_setup_socket(CVE-2024-42246)

    net: hns3: fix kernel crash when 1588 is received on HIP08 devices(CVE-2024-26881)

    net: phy: fix phy_get_internal_delay accessing an empty array(CVE-2024-27047)

    net: USB: Fix wrong-direction WARNING in plusb.c(CVE-2023-52742)

    netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers(CVE-2024-42070)

    netfilter: nfnetlink_queue: acquire rcu_read_lock() in instance_destroy_rcu(CVE-2024-36286)

    netfilter: tproxy: bail out if IP has been disabled on the device(CVE-2024-36270)

    net-sysfs: add check for netdevice being present to speed_show(CVE-2022-48850)

    null_blk: fix validation of block size(CVE-2024-41077)

    nvme-fabrics: use reserved tag for reg read/write command(CVE-2024-41082)

    nvmet: always initialize cqe.result(CVE-2024-41079)

    nvmet: fix a possible leak when destroy a ctrl during qp establishment(CVE-2024-42152)

    nvme-tcp: fix possible use-after-free in transport error_recovery work(CVE-2022-48789)

    of: module: prevent NULL pointer dereference in vsnprintf()(CVE-2024-35878)

    pinctrl: fix deadlock in create_pinctrl() when handling -EPROBE_DEFER(CVE-2024-42090)

    powerpc/powernv: Add a null pointer check in opal_powercap_init()(CVE-2023-52696)

    ppp: reject claimed-as-LCP but actually malformed packets(CVE-2024-41044)

    RDMA/restrack: Fix potential invalid address access(CVE-2024-42080)

    sched/deadline: Fix task_struct reference leak(CVE-2024-41023)

    scsi: qedf: Make qedf_execute_tmf() non-preemptible(CVE-2024-42124)

    skmsg: Skip zero length skb in sk_msg_recvmsg(CVE-2024-41048)

    tap: add missing verification for short frame(CVE-2024-41090)

    tcp_metrics: validate source addr length(CVE-2024-42154)

    tun: add missing verification for short frame(CVE-2024-41091)

    udp: do not accept non-tunnel GSO skbs landing in a tunnel(CVE-2024-35884)

    udp: Set SOCK_RCU_FREE earlier in udp_lib_get_port().(CVE-2024-41041)

    usb: atm: cxacru: fix endpoint checking in cxacru_bind()(CVE-2024-41097)

    usb: usbtmc: Fix bug in pipe direction for control transfers(CVE-2022-48834)

    x86/fpu: Keep xfd_state in sync with MSR_IA32_XFD(CVE-2024-35801)

    x86: stop playing stack games in profile_pc()(CVE-2024-42096)

    xdp: Remove WARN() from __xdp_reg_mem_model(CVE-2024-42082)

    xfs: add bounds checking to xlog_recover_process_data(CVE-2024-41014)

    xfs: don't walk off the end of a directory data block(CVE-2024-41013)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2806
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e97bb6de");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42148");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/04");

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
  "bpftool-5.10.0-136.12.0.86.h2130.eulerosv2r12",
  "kernel-5.10.0-136.12.0.86.h2130.eulerosv2r12",
  "kernel-abi-stablelists-5.10.0-136.12.0.86.h2130.eulerosv2r12",
  "kernel-tools-5.10.0-136.12.0.86.h2130.eulerosv2r12",
  "kernel-tools-libs-5.10.0-136.12.0.86.h2130.eulerosv2r12",
  "python3-perf-5.10.0-136.12.0.86.h2130.eulerosv2r12"
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
