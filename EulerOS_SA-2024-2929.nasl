#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211805);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/25");

  script_cve_id(
    "CVE-2022-48790",
    "CVE-2022-48828",
    "CVE-2022-48899",
    "CVE-2022-48910",
    "CVE-2022-48911",
    "CVE-2022-48912",
    "CVE-2022-48924",
    "CVE-2022-48930",
    "CVE-2022-48933",
    "CVE-2022-48935",
    "CVE-2022-48937",
    "CVE-2023-52898",
    "CVE-2023-52903",
    "CVE-2024-39509",
    "CVE-2024-40901",
    "CVE-2024-40966",
    "CVE-2024-41035",
    "CVE-2024-41042",
    "CVE-2024-41087",
    "CVE-2024-41089",
    "CVE-2024-41098",
    "CVE-2024-42145",
    "CVE-2024-42232",
    "CVE-2024-42244",
    "CVE-2024-42265",
    "CVE-2024-42283",
    "CVE-2024-42284",
    "CVE-2024-42285",
    "CVE-2024-42289",
    "CVE-2024-42302",
    "CVE-2024-42304",
    "CVE-2024-42305",
    "CVE-2024-42306",
    "CVE-2024-42321",
    "CVE-2024-42322",
    "CVE-2024-43828",
    "CVE-2024-43830",
    "CVE-2024-43840",
    "CVE-2024-43846",
    "CVE-2024-43853",
    "CVE-2024-43861",
    "CVE-2024-43866",
    "CVE-2024-43882"
  );

  script_name(english:"EulerOS 2.0 SP12 : kernel (EulerOS-SA-2024-2929)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    RDMA/ib_srp: Fix a deadlock(CVE-2022-48930)

    netfilter: fix use-after-free in __nf_register_net_hook()(CVE-2022-48912)

    protect the fetch of -fd[fd] in do_dup2() from mispredictions(CVE-2024-42265)

    io_uring: add a schedule point in io_add_buffers()(CVE-2022-48937)

    ext4: check dot and dotdot of dx_root before making dir indexed(CVE-2024-42305)

    netfilter: nf_queue: fix possible use-after-free(CVE-2022-48911)

    cgroup/cpuset: Prevent UAF in proc_cpuset_show()(CVE-2024-43853)

    net: ipv6: ensure we call ipv6_mc_down() at most once(CVE-2022-48910)

    netfilter: nf_tables: fix memory leak during stateful obj update(CVE-2022-48933)

    netfilter: nf_tables: unregister flowtable hooks on netns exit(CVE-2022-48935)

    thermal: int340x: fix memory leak in int3400_notify()(CVE-2022-48924)

    scsi: qla2xxx: During vport delete send async logout explicitly(CVE-2024-42289)

    udf: Avoid using corrupted block bitmap buffer(CVE-2024-42306)

    lib: objagg: Fix general protection fault(CVE-2024-43846)

    net/mlx5: Always drain health in shutdown callback(CVE-2024-43866)

    exec: Fix ToCToU between perm check and set-uid/gid usage(CVE-2024-43882)

    net: usb: qmi_wwan: fix memory leak for not ip packets(CVE-2024-43861)

    io_uring: lock overflowing for IOPOLL(CVE-2023-52903)

    drm/virtio: Fix GEM handle creation UAF(CVE-2022-48899)

    xhci: Fix null pointer dereference when host dies(CVE-2023-52898)

    nvme: fix a possible use-after-free in controller reset during load(CVE-2022-48790)

    drm/ nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_hd_modes(CVE-2024-41089)

    ipvs: properly dereference pe in ip_vs_add_service(CVE-2024-42322)

    bpf, arm64: Fix trampoline for BPF_TRAMP_F_CALL_ORIG(CVE-2024-43840)

    net: flow_dissector: use DEBUG_NET_WARN_ON_ONCE(CVE-2024-42321)

    RDMA/iwcm: Fix a use-after-free related to destroying CM IDs(CVE-2024-42285)

    tipc: Return non-zero value from tipc_udp_addr2str() on error(CVE-2024-42284)

    ext4: fix infinite loop when replaying fast_commit(CVE-2024-43828)

    ext4: make sure the first directory block is not a hole(CVE-2024-42304)

    PCI/DPC: Fix use-after-free on concurrent DPC and hot-removal(CVE-2024-42302)

    net: nexthop: Initialize all fields in dumped nexthops(CVE-2024-42283)

    leds: trigger: Unregister sysfs attributes before calling deactivate()(CVE-2024-43830)

    IB/core: Implement a limit on UMAD receive List(CVE-2024-42145)

    NFSD: Fix ia_size underflow(CVE-2022-48828)

    netfilter: nf_tables: prefer nft_chain_validate(CVE-2024-41042)

    HID: core: remove unnecessary WARN_ON() in implement()(CVE-2024-39509)

    USB: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor(CVE-2024-41035)

    tty: add the option to have a tty reject a new ldisc(CVE-2024-40966)

    libceph: fix race between delayed_work() and ceph_monc_stop()(CVE-2024-42232)

    ata: libata-core: Fix null pointer dereference on error(CVE-2024-41098)

    USB: serial: mos7840: fix crash on resume(CVE-2024-42244)

    ata: libata-core: Fix double free on error(CVE-2024-41087)

    scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory(CVE-2024-40901)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2929
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6590bcb0");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42302");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/25");

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
  "bpftool-5.10.0-136.12.0.86.h2177.eulerosv2r12",
  "kernel-5.10.0-136.12.0.86.h2177.eulerosv2r12",
  "kernel-abi-stablelists-5.10.0-136.12.0.86.h2177.eulerosv2r12",
  "kernel-tools-5.10.0-136.12.0.86.h2177.eulerosv2r12",
  "kernel-tools-libs-5.10.0-136.12.0.86.h2177.eulerosv2r12",
  "python3-perf-5.10.0-136.12.0.86.h2177.eulerosv2r12"
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
