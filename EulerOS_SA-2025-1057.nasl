#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214178);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/14");

  script_cve_id(
    "CVE-2021-47344",
    "CVE-2021-47345",
    "CVE-2022-48946",
    "CVE-2022-48949",
    "CVE-2022-48956",
    "CVE-2022-48969",
    "CVE-2022-48978",
    "CVE-2022-49000",
    "CVE-2022-49002",
    "CVE-2022-49014",
    "CVE-2022-49021",
    "CVE-2023-52653",
    "CVE-2023-52742",
    "CVE-2024-44958",
    "CVE-2024-45021",
    "CVE-2024-45025",
    "CVE-2024-46673",
    "CVE-2024-46739",
    "CVE-2024-46744",
    "CVE-2024-46750",
    "CVE-2024-46777",
    "CVE-2024-46826",
    "CVE-2024-46829",
    "CVE-2024-46859",
    "CVE-2024-47685",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47698",
    "CVE-2024-47701",
    "CVE-2024-47742",
    "CVE-2024-47745",
    "CVE-2024-49855",
    "CVE-2024-49860",
    "CVE-2024-49881",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49884",
    "CVE-2024-49889",
    "CVE-2024-49894",
    "CVE-2024-49959",
    "CVE-2024-49995",
    "CVE-2024-50033",
    "CVE-2024-50035",
    "CVE-2024-50036",
    "CVE-2024-50058",
    "CVE-2024-50073",
    "CVE-2024-50115",
    "CVE-2024-50154",
    "CVE-2024-50179",
    "CVE-2024-50195",
    "CVE-2024-50199",
    "CVE-2024-50258",
    "CVE-2024-50262",
    "CVE-2024-50278",
    "CVE-2024-50279",
    "CVE-2024-50301"
  );

  script_name(english:"EulerOS 2.0 SP9 : kernel (EulerOS-SA-2025-1057)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory(CVE-2024-50115)

    tcp/dccp: Don't use timer_pending() in reqsk_queue_unlink().(CVE-2024-50154)

    bpf: Fix out-of-bounds write in trie_get_next_key().(CVE-2024-50262)

    security/keys: fix slab-out-of-bounds in key_task_permission(CVE-2024-50301)

    dm cache: fix potential out-of-bounds access on the first resume(CVE-2024-50278)

    dm cache: fix out-of-bounds access to the dirty bitset when resizing(CVE-2024-50279)

    fix bitmap corruption on close_range() with CLOSE_RANGE_UNSHARE(CVE-2024-45025)

    net: USB: Fix wrong-direction WARNING in plusb.c(CVE-2023-52742)

    In the Linux kernel, the following vulnerability has been resolved:memcg_write_event_control(): fix a
    user-triggerable oops  we are *not* guaranteed that anything past the terminating NUL is mapped (let alone
    initialized with anything sane).(CVE-2024-45021)

    udf: Avoid excessive partition lengths(CVE-2024-46777)

    uio_hv_generic: Fix kernel NULL pointer dereference in hv_uio_rescind (CVE-2024-46739)

    Squashfs: sanity check symbolic link size(CVE-2024-46744)

    PCI: Add missing bridge lock to pci_bus_lock()(CVE-2024-46750)

    platform/x86: panasonic-laptop: Fix SINF array out of bounds accesses(CVE-2024-46859)

    ELF: fix kernel.randomize_va_space double read(CVE-2024-46826)

    rtmutex: Drop rt_mutex::wait_lock before scheduling(CVE-2024-46829)

    sched/smt: Fix unbalance sched_smt_present dec/inc(CVE-2024-44958)

    scsi: aacraid: Fix double-free on probe failure(CVE-2024-46673)

    media: zr364xx: fix memory leak in zr364xx_start_readpipe(CVE-2021-47344)

    RDMA/cma: Fix rdma_resolve_route() memory leak(CVE-2021-47345)

    ACPI: sysfs: validate return type of _STR method(CVE-2024-49860)

    mm: call the security_mmap_file() LSM hook in remap_file_pages().(CVE-2024-47745)

    netfilter: nf_reject_ipv6: fix nf_reject_ip6_tcphdr_put()(CVE-2024-47685)

    drivers: media: dvb-frontends/rtl2830: fix an out-of-bounds write error(CVE-2024-47697)

    drivers: media: dvb-frontends/rtl2832: fix an out-of-bounds write error(CVE-2024-47698)

    tipc: guard against string buffer overrun(CVE-2024-49995)

    ext4: fix double brelse() the buffer of the extents path(CVE-2024-49882)

    net: tun: Fix use-after-free in tun_detach()(CVE-2022-49014)

    ppp: fix ppp_async_encode() illegal access(CVE-2024-50035)

    serial: protect uart_port_dtr_rts() in uart_shutdown() too(CVE-2024-50058)

    net: do not delay dst_entries_add() in dst_release()(CVE-2024-50036)

    HID: core: fix shift-out-of-bounds in hid_report_raw_event(CVE-2022-48978)

    slip: make slhc_remember() more robust against malicious packets(CVE-2024-50033)

    ipv6: avoid use-after-free in ip6_fragment()(CVE-2022-48956)

    udf: Fix preallocation discarding at indirect extent boundary(CVE-2022-48946)

    net: phy: fix null-ptr-deref while probe() failed(CVE-2022-49021)

    igb: Initialize mailbox message for VF reset(CVE-2022-48949)

    xen-netfront: Fix NULL sring after live migration(CVE-2022-48969)

    ext4: aovid use-after-free in ext4_ext_insert_extent().(CVE-2024-49883)

    jbd2: stop waiting for space when jbd2_cleanup_journal_tail() returns error(CVE-2024-49959)

    ext4: fix slab-use-after-free in ext4_split_extent_at().(CVE-2024-49884)

    ext4: update orig_path in ext4_find_extent().(CVE-2024-49881)

    ext4: avoid use-after-free in ext4_ext_show_leaf().(CVE-2024-49889)

    ext4: avoid OOB when system.data xattr changes underneath the filesystem(CVE-2024-47701)

    firmware_loader: Block path traversal(CVE-2024-47742)

    iommu/vt-d: Fix PCI device refcount leak in dmar_dev_scope_init()(CVE-2022-49002)

    drm/amd/display: Fix index out of bounds in degamma hardware format translation(CVE-2024-49894)

    tty: n_gsm: Fix use-after-free in gsm_cleanup_mux(CVE-2024-50073)

    nbd: fix race between timeout and normal completion(CVE-2024-49855)

    iommu/vt-d: Fix PCI device refcount leak in has_external_pci()(CVE-2022-49000)

    RDMA/iwcm: Fix WARNING:at_kernel/workqueue.c:#check_flush_dependency(CVE-2024-47696)

    posix-clock: Fix missing timespec64 check in pc_clock_settime().(CVE-2024-50195)

    ceph: remove the incorrect Fw reference check when dirtying pages(CVE-2024-50179)

    net: fix crash when config small gso_max_size/gso_ipv4_max_size(CVE-2024-50258)

    mm/swapfile: skip HugeTLB pages for unuse_vma(CVE-2024-50199)

    kernel:SUNRPC: fix a memleak in gss_import_v2_context(CVE-2023-52653)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1057
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6d0d28c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/14");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.18.0-147.5.1.6.h1486.eulerosv2r9",
  "kernel-tools-4.18.0-147.5.1.6.h1486.eulerosv2r9",
  "kernel-tools-libs-4.18.0-147.5.1.6.h1486.eulerosv2r9",
  "python3-perf-4.18.0-147.5.1.6.h1486.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
