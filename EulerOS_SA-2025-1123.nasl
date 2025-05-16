#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214406);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/21");

  script_cve_id(
    "CVE-2021-47261",
    "CVE-2021-47274",
    "CVE-2021-47311",
    "CVE-2021-47354",
    "CVE-2021-47378",
    "CVE-2021-47391",
    "CVE-2021-47456",
    "CVE-2021-47483",
    "CVE-2021-47496",
    "CVE-2021-47497",
    "CVE-2021-47541",
    "CVE-2021-47548",
    "CVE-2021-47576",
    "CVE-2021-47589",
    "CVE-2022-48732",
    "CVE-2022-48742",
    "CVE-2022-48754",
    "CVE-2022-48788",
    "CVE-2022-48855",
    "CVE-2022-48912",
    "CVE-2023-52832",
    "CVE-2023-52880",
    "CVE-2023-52881",
    "CVE-2023-52885",
    "CVE-2024-26852",
    "CVE-2024-26865",
    "CVE-2024-26923",
    "CVE-2024-26934",
    "CVE-2024-26976",
    "CVE-2024-35789",
    "CVE-2024-35950",
    "CVE-2024-35955",
    "CVE-2024-35960",
    "CVE-2024-36016",
    "CVE-2024-36904",
    "CVE-2024-36905",
    "CVE-2024-36940",
    "CVE-2024-36971",
    "CVE-2024-38538",
    "CVE-2024-38541",
    "CVE-2024-38559",
    "CVE-2024-38588",
    "CVE-2024-39480",
    "CVE-2024-39487",
    "CVE-2024-41087",
    "CVE-2024-42145",
    "CVE-2024-42148",
    "CVE-2024-42154",
    "CVE-2024-42228",
    "CVE-2024-42285",
    "CVE-2024-43882",
    "CVE-2024-44987",
    "CVE-2024-46673",
    "CVE-2024-46722",
    "CVE-2024-46723",
    "CVE-2024-46743",
    "CVE-2024-46744",
    "CVE-2024-46756",
    "CVE-2024-46757",
    "CVE-2024-46758",
    "CVE-2024-46759",
    "CVE-2024-46800",
    "CVE-2024-46816",
    "CVE-2024-47685"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2025-1123)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    kernel: drm/sched: Avoid data corruptions(CVE-2021-47354)

    drm/sched: Avoid data corruptions(CVE-2024-46759)

    hwmon: (lm95234) Fix underflows seen when writing limit attributes(CVE-2024-46758)

    exec: Fix ToCToU between perm check and set-uid/gid usage(CVE-2024-43882)

    Squashfs: sanity check symbolic link size(CVE-2024-46744)

    scsi: aacraid: Fix double-free on probe failure(CVE-2024-46673)

    ata: libata-core: Fix double free on error(CVE-2024-41087)

    drm/amdgpu: fix ucode out-of-bounds read warning(CVE-2024-46723)

    tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc(CVE-2023-52880)

    drm/amdgpu: fix ucode out-of-bounds read warning(CVE-2024-42228)

    hwmon: (nct6775-core) Fix underflows seen when writing limit attributes(CVE-2024-46757)

    kernel:scsi: qedf: Ensure the copied buf is NUL terminated(CVE-2024-38559)

    drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links(CVE-2024-46816)

    of/irq: Prevent device address out-of-bounds read in interrupt map walk(CVE-2024-46743)

    net/tls: Fix flipped sign in tls_err_abort() calls(CVE-2021-47496)

    netfilter: fix use-after-free in __nf_register_net_hook()(CVE-2022-48912)

    SUNRPC: Fix UAF in svc_tcp_listen_data_ready()(CVE-2023-52885)

    drm/ nouveau: fix off by one in BIOS boundary checking(CVE-2022-48732)

    kernel:RDMA/cma: Ensure rdma_addr_cancel() happens before issuing more requests(CVE-2021-47391)

    kernel:sctp: fix kernel-infoleak for SCTP sockets(CVE-2022-48855)

    igbvf: fix double free in `igbvf_probe`(CVE-2021-47589)

    rtnetlink: make sure to refresh master_dev/m_ops in __rtnl_newlink()(CVE-2022-48742)

    phylib: fix potential use-after-free(CVE-2022-48754)

    kernel:net: qcom/emac: fix UAF in emac_remove(CVE-2021-47311)

    kernel:tcp: do not accept ACK of bytes we never sent(CVE-2023-52881)

    kernel:net/mlx4_en: Fix an use-after-free bug in mlx4_en_try_alloc_resources()(CVE-2021-47541)

    net/ipv6: avoid possible UAF in ip6_route_mpath_notify()(CVE-2024-26852)

    kernel:tty: n_gsm: fix possible out-of-bounds in gsm0_receive()(CVE-2024-36016)

    kernel:tcp: Use refcount_inc_not_zero() in tcp_twsk_unique().(CVE-2024-36904)

    kernel: pinctrl: core: delete incorrect free in pinctrl_enable()(CVE-2024-36940)

    drm/client: Fully protect modes[] with dev-mode_config.mutex(CVE-2024-35950)

    USB: core: Fix deadlock in usb_deauthorize_interface()(CVE-2024-26934)

    KVM: Always flush async #PF workqueue when vCPU is being destroyed(CVE-2024-26976)

    sch/ netem: fix use after free in netem_dequeue(CVE-2024-46800)

    ipv6: prevent UAF in ip6_send_skb()(CVE-2024-44987)

    RDMA/iwcm: Fix a use-after-free related to destroying CM IDs(CVE-2024-42285)

    IB/core: Implement a limit on UMAD receive List(CVE-2024-42145)

    bnx2x: Fix multiple UBSAN array-index-out-of-bounds(CVE-2024-42148)

    tcp_metrics: validate source addr length(CVE-2024-42154)

    kernel:bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set()(CVE-2024-39487)

    kernel:regmap: Fix possible double-free in regcache_rbtree_exit()(CVE-2021-47483)

    kernel:kprobes: Fix possible use-after-free issue on kprobe registration(CVE-2024-35955)

    nvme-rdma: destroy cm id before destroy qp to avoid use after free(CVE-2021-47378)

    nvmem: Fix shift-out-of-bound (UBSAN) with byte size cells(CVE-2021-47497)

    kernel:ftrace: Fix possible use-after-free issue in ftrace_location()(CVE-2024-38588)

    kernel:net: bridge: xmit: make sure we have at least eth header len bytes(CVE-2024-38538)

    kernel:net: fix __dst_negative_advice() race(CVE-2024-36971)

    kernel:of: module: add buffer overflow check in of_modalias()(CVE-2024-38541)

    kernel:tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets(CVE-2024-36905)

    wifi: mac80211: don't return unset power in ieee80211_get_tx_power()(CVE-2023-52832)

    kernel:ethernet: hisilicon: hns: hns_dsaf_misc: fix a possible array overflow in
    hns_dsaf_ge_srst_by_port()(CVE-2021-47548)

    kernel:net/mlx5: Properly link new fs rules into the tree(CVE-2024-35960)

    tracing: Correct the length check which causes memory corruption(CVE-2021-47274)

    drm/amdgpu: fix mc_data out-of-bounds read warning(CVE-2024-46722)

    kernel:kdb: Fix buffer overflow during tab-complete(CVE-2024-39480)

    kernel: IB/mlx5: Fix initializing CQ fragments buffer(CVE-2021-47261)

    nvme-rdma: fix possible use-after-free in transport error_recovery work(CVE-2022-48788)

    scsi: scsi_debug: Sanity check block descriptor length in resp_mode_select()(CVE-2021-47576)

    hwmon: (w83627ehf) Fix underflows seen when writing limit attributes(CVE-2024-46756)

    can: peak_pci: peak_pci_remove(): fix UAF(CVE-2021-47456)

    kernel: wifi: mac80211: check/clear fast rx for non-4addr sta VLAN changes(CVE-2024-35789)

    rds: tcp: Fix use-after-free of net in reqsk_timer_handler().(CVE-2024-26865)

    netfilter: nf_reject_ipv6: fix nf_reject_ip6_tcphdr_put()(CVE-2024-47685)

    af_unix: Fix garbage collector racing against connect()(CVE-2024-26923)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1123
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?620ddc07");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-4.19.36-vhulk1907.1.0.h1665.eulerosv2r8",
  "kernel-4.19.36-vhulk1907.1.0.h1665.eulerosv2r8",
  "kernel-devel-4.19.36-vhulk1907.1.0.h1665.eulerosv2r8",
  "kernel-headers-4.19.36-vhulk1907.1.0.h1665.eulerosv2r8",
  "kernel-tools-4.19.36-vhulk1907.1.0.h1665.eulerosv2r8",
  "kernel-tools-libs-4.19.36-vhulk1907.1.0.h1665.eulerosv2r8",
  "perf-4.19.36-vhulk1907.1.0.h1665.eulerosv2r8",
  "python-perf-4.19.36-vhulk1907.1.0.h1665.eulerosv2r8",
  "python3-perf-4.19.36-vhulk1907.1.0.h1665.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
