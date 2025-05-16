#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210643);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2021-47400",
    "CVE-2021-47423",
    "CVE-2021-47434",
    "CVE-2022-48732",
    "CVE-2022-48788",
    "CVE-2022-48828",
    "CVE-2022-48879",
    "CVE-2022-48899",
    "CVE-2022-48943",
    "CVE-2023-52880",
    "CVE-2023-52898",
    "CVE-2024-26852",
    "CVE-2024-26921",
    "CVE-2024-40959",
    "CVE-2024-40978",
    "CVE-2024-41012",
    "CVE-2024-41014",
    "CVE-2024-41020",
    "CVE-2024-41035",
    "CVE-2024-41087",
    "CVE-2024-41095",
    "CVE-2024-42070",
    "CVE-2024-42084",
    "CVE-2024-42102",
    "CVE-2024-42131",
    "CVE-2024-42145",
    "CVE-2024-42154",
    "CVE-2024-42244",
    "CVE-2024-42265",
    "CVE-2024-42285",
    "CVE-2024-42286",
    "CVE-2024-42289",
    "CVE-2024-42292",
    "CVE-2024-42304",
    "CVE-2024-42305",
    "CVE-2024-42312",
    "CVE-2024-43830",
    "CVE-2024-43853",
    "CVE-2024-43856",
    "CVE-2024-43861",
    "CVE-2024-43871",
    "CVE-2024-43882",
    "CVE-2024-43890",
    "CVE-2024-43892",
    "CVE-2024-43893",
    "CVE-2024-43914",
    "CVE-2024-44944",
    "CVE-2024-44987",
    "CVE-2024-45006",
    "CVE-2024-46800"
  );

  script_name(english:"EulerOS 2.0 SP10 : kernel (EulerOS-SA-2024-2888)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    scsi: qedi: Fix crash while reading debugfs attribute(CVE-2024-40978)

    drm/ nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_ld_modes(CVE-2024-41095)

    drm/ nouveau/debugfs: fix file release memory leak(CVE-2021-47423)

    USB: serial: mos7840: fix crash on resume(CVE-2024-42244)

    NFSD: Fix ia_size underflow(CVE-2022-48828)

    xhci: Fix command ring pointer corruption while aborting a command(CVE-2021-47434)

    ata: libata-core: Fix double free on error(CVE-2024-41087)

    xfs: add bounds checking to xlog_recover_process_data(CVE-2024-41014)

    ftruncate: pass a signed offset(CVE-2024-42084)

    ext4: check dot and dotdot of dx_root before making dir indexed(CVE-2024-42305)

    ext4: make sure the first directory block is not a hole(CVE-2024-42304)

    leds: trigger: Unregister sysfs attributes before calling deactivate()(CVE-2024-43830)

    Revert 'mm/writeback: fix possible divide-by-zero in wb_dirty_limits(), again'(CVE-2024-42102)

    filelock: Remove locks reliably when fcntl/close race is detected(CVE-2024-41012)

    filelock: Fix fcntl/close race recovery compat path(CVE-2024-41020)

    protect the fetch of -fd[fd] in do_dup2() from mispredictions(CVE-2024-42265)

    scsi: qla2xxx: During vport delete send async logout explicitly(CVE-2024-42289)

    exec: Fix ToCToU between perm check and set-uid/gid usage(CVE-2024-43882)

    tracing: Fix overflow in get_free_elt()(CVE-2024-43890)

    USB: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor(CVE-2024-41035)

    xhci: Fix null pointer dereference when host dies(CVE-2023-52898)

    mm: avoid overflows in dirty throttling logic(CVE-2024-42131)

    kobject_uevent: Fix OOB access within zap_modalias_env()(CVE-2024-42292)

    sysctl: always initialize i_uid/i_gid(CVE-2024-42312)

    scsi: qla2xxx: validate nvme_local_port correctly(CVE-2024-42286)

    serial: core: check uartclk for zero to avoid divide by zero(CVE-2024-43893)

    tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc(CVE-2023-52880)

    memcg: protect concurrent access to mem_cgroup_idr(CVE-2024-43892)

    dma: fix call order in dmam_free_coherent(CVE-2024-43856)

    drm/ nouveau: fix off by one in BIOS boundary checking(CVE-2022-48732)

    IB/core: Implement a limit on UMAD receive List(CVE-2024-42145)

    drm/virtio: Fix GEM handle creation UAF(CVE-2022-48899)

    cgroup/cpuset: Prevent UAF in proc_cpuset_show()(CVE-2024-43853)

    net: usb: qmi_wwan: fix memory leak for not ip packets(CVE-2024-43861)

    md/raid5: avoid BUG_ON() while continue reshape after reassembling(CVE-2024-43914)

    netfilter: ctnetlink: use helper function to calculate expect ID(CVE-2024-44944)

    RDMA/iwcm: Fix a use-after-free related to destroying CM IDs(CVE-2024-42285)

    KVM: x86/mmu: make apf token non-zero to fix bug(CVE-2022-48943)

    efi: fix NULL-deref in init error path(CVE-2022-48879)

    nvme-rdma: fix possible use-after-free in transport error_recovery work(CVE-2022-48788)

    devres: Fix memory leakage caused by driver API devm_free_percpu()(CVE-2024-43871)

    netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers(CVE-2024-42070)

    xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr()(CVE-2024-40959)

    xhci: Fix Panther point NULL pointer deref at full-speed re-enumeration(CVE-2024-45006)

    tcp_metrics: validate source addr length(CVE-2024-42154)

    inet: inet_defrag: prevent sk release while still in use(CVE-2024-26921)

    net: hns3: do not allow call hns3_nic_net_open repeatedly(CVE-2021-47400)

    net/ipv6: avoid possible UAF in ip6_route_mpath_notify()(CVE-2024-26852)

    ipv6: prevent UAF in ip6_send_skb()(CVE-2024-44987)

    sch/ netem: fix use after free in netem_dequeue(CVE-2024-46800)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2888
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b74d2ddd");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46800");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.19.90-vhulk2211.3.0.h1912.eulerosv2r10",
  "kernel-abi-stablelists-4.19.90-vhulk2211.3.0.h1912.eulerosv2r10",
  "kernel-tools-4.19.90-vhulk2211.3.0.h1912.eulerosv2r10",
  "kernel-tools-libs-4.19.90-vhulk2211.3.0.h1912.eulerosv2r10",
  "python3-perf-4.19.90-vhulk2211.3.0.h1912.eulerosv2r10"
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
