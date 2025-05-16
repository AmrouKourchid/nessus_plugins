#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210652);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2021-47296",
    "CVE-2021-47356",
    "CVE-2021-47408",
    "CVE-2022-48863",
    "CVE-2022-48924",
    "CVE-2022-48930",
    "CVE-2022-48943",
    "CVE-2023-52885",
    "CVE-2023-52898",
    "CVE-2023-52915",
    "CVE-2024-38659",
    "CVE-2024-39509",
    "CVE-2024-40953",
    "CVE-2024-40959",
    "CVE-2024-41012",
    "CVE-2024-41014",
    "CVE-2024-41020",
    "CVE-2024-41035",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41069",
    "CVE-2024-41087",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-42070",
    "CVE-2024-42084",
    "CVE-2024-42096",
    "CVE-2024-42102",
    "CVE-2024-42131",
    "CVE-2024-42145",
    "CVE-2024-42148",
    "CVE-2024-42154",
    "CVE-2024-42223",
    "CVE-2024-42229",
    "CVE-2024-42232",
    "CVE-2024-42265",
    "CVE-2024-42280",
    "CVE-2024-42284",
    "CVE-2024-42285",
    "CVE-2024-42286",
    "CVE-2024-42288",
    "CVE-2024-42289",
    "CVE-2024-42292",
    "CVE-2024-42301",
    "CVE-2024-42305",
    "CVE-2024-42312",
    "CVE-2024-43853",
    "CVE-2024-43856",
    "CVE-2024-43871",
    "CVE-2024-43882",
    "CVE-2024-43890",
    "CVE-2024-43892",
    "CVE-2024-43893",
    "CVE-2024-43900",
    "CVE-2024-43914",
    "CVE-2024-44948",
    "CVE-2024-44987",
    "CVE-2024-45006",
    "CVE-2024-46738",
    "CVE-2024-46800"
  );

  script_name(english:"EulerOS 2.0 SP10 : kernel (EulerOS-SA-2024-2907)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    SUNRPC: Fix UAF in svc_tcp_listen_data_ready()(CVE-2023-52885)

    HID: core: remove unnecessary WARN_ON() in implement()(CVE-2024-39509)

    xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr()(CVE-2024-40959)

    x86: stop playing stack games in profile_pc()(CVE-2024-42096)

    ASoC: topology: Fix references to freed memory(CVE-2024-41069)

    crypto: aead,cipher - zeroize key buffer after use(CVE-2024-42229)

    ata: libata-core: Fix double free on error(CVE-2024-41087)

    media: dvb-frontends: tda10048: Fix integer overflow(CVE-2024-42223)

    xfs: add bounds checking to xlog_recover_process_data(CVE-2024-41014)

    USB: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor(CVE-2024-41035)

    ftruncate: pass a signed offset(CVE-2024-42084)

    filelock: Remove locks reliably when fcntl/close race is detected(CVE-2024-41012)

    filelock: Fix fcntl/close race recovery compat path(CVE-2024-41020)

    thermal: int340x: fix memory leak in int3400_notify()(CVE-2022-48924)

    ext4: check dot and dotdot of dx_root before making dir indexed(CVE-2024-42305)

    scsi: qla2xxx: During vport delete send async logout explicitly(CVE-2024-42289)

    scsi: qla2xxx: Fix for possible memory corruption(CVE-2024-42288)

    exec: Fix ToCToU between perm check and set-uid/gid usage(CVE-2024-43882)

    tracing: Fix overflow in get_free_elt()(CVE-2024-43890)

    scsi: qla2xxx: validate nvme_local_port correctly(CVE-2024-42286)

    xhci: Fix null pointer dereference when host dies(CVE-2023-52898)

    dev/parport: fix the array out-of-bounds risk(CVE-2024-42301)

    mm: avoid overflows in dirty throttling logic(CVE-2024-42131)

    IB/core: Implement a limit on UMAD receive List(CVE-2024-42145)

    RDMA/iwcm: Fix a use-after-free related to destroying CM IDs(CVE-2024-42285)

    tipc: Return non-zero value from tipc_udp_addr2str() on error(CVE-2024-42284)

    netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers(CVE-2024-42070)

    bnx2x: Fix multiple UBSAN array-index-out-of-bounds(CVE-2024-42148)

    libceph: fix race between delayed_work() and ceph_monc_stop()(CVE-2024-42232)

    mISDN: Fix a use after free in hfcmulti_tx()(CVE-2024-42280)

    cgroup/cpuset: Prevent UAF in proc_cpuset_show()(CVE-2024-43853)

    protect the fetch of -fd[fd] in do_dup2() from mispredictions(CVE-2024-42265)

    kobject_uevent: Fix OOB access within zap_modalias_env()(CVE-2024-42292)

    sysctl: always initialize i_uid/i_gid(CVE-2024-42312)

    serial: core: check uartclk for zero to avoid divide by zero(CVE-2024-43893)

    KVM: PPC: Fix kvm_arch_vcpu_ioctl vcpu_load leak(CVE-2021-47296)

    KVM: Fix a data race on last_boosted_vcpu in kvm_vcpu_on_spin()(CVE-2024-40953)

    KVM: x86/mmu: make apf token non-zero to fix bug(CVE-2022-48943)

    udp: Set SOCK_RCU_FREE earlier in udp_lib_get_port().(CVE-2024-41041)

    ppp: reject claimed-as-LCP but actually malformed packets(CVE-2024-41044)

    enic: Validate length of nl attributes in enic_set_vf_port(CVE-2024-38659)

    RDMA/ib_srp: Fix a deadlock(CVE-2022-48930)

    devres: Fix memory leakage caused by driver API devm_free_percpu()(CVE-2024-43871)

    dma: fix call order in dmam_free_coherent(CVE-2024-43856)

    memcg: protect concurrent access to mem_cgroup_idr(CVE-2024-43892)

    md/raid5: avoid BUG_ON() while continue reshape after reassembling(CVE-2024-43914)

    mISDN: fix possible use-after-free in HFC_cleanup()(CVE-2021-47356)

    mISDN: Fix memory leak in dsp_pipeline_build()(CVE-2022-48863)

    media: xc2028: avoid use-after-free in load_firmware_cb()(CVE-2024-43900)

    tcp_metrics: validate source addr length(CVE-2024-42154)

    x86/mtrr: Check if fixed MTRRs exist before saving them(CVE-2024-44948)

    tap: add missing verification for short frame(CVE-2024-41090)

    tun: add missing verification for short frame(CVE-2024-41091)

    media: dvb-usb-v2: af9035: Fix null-ptr-deref in af9035_i2c_master_xfer(CVE-2023-52915)

    xhci: Fix Panther point NULL pointer deref at full-speed re-enumeration(CVE-2024-45006)

    Revert 'mm/writeback: fix possible divide-by-zero in wb_dirty_limits(), again'(CVE-2024-42102)

    ipv6: prevent UAF in ip6_send_skb()(CVE-2024-44987)

    kernel: netfilter: conntrack: serialize hash resizes and cleanups(CVE-2021-47408)

    sch/ netem: fix use after free in netem_dequeue(CVE-2024-46800)

    VMCI: Fix use-after-free when removing resource in vmci_resource_remove()(CVE-2024-46738)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2907
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a038b66e");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46800");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.18.0-147.5.2.19.h1720.eulerosv2r10",
  "kernel-abi-stablelists-4.18.0-147.5.2.19.h1720.eulerosv2r10",
  "kernel-tools-4.18.0-147.5.2.19.h1720.eulerosv2r10",
  "kernel-tools-libs-4.18.0-147.5.2.19.h1720.eulerosv2r10",
  "python3-perf-4.18.0-147.5.2.19.h1720.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

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
