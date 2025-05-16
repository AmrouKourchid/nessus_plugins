#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.15-2025-060.
##

include('compat.inc');

if (description)
{
  script_id(213683);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2023-52913",
    "CVE-2024-26718",
    "CVE-2024-38538",
    "CVE-2024-41080",
    "CVE-2024-49996",
    "CVE-2024-50010",
    "CVE-2024-50036",
    "CVE-2024-50058",
    "CVE-2024-50072",
    "CVE-2024-50082",
    "CVE-2024-50083",
    "CVE-2024-50085",
    "CVE-2024-50099",
    "CVE-2024-50101",
    "CVE-2024-50110",
    "CVE-2024-50115",
    "CVE-2024-50127",
    "CVE-2024-50128",
    "CVE-2024-50131",
    "CVE-2024-50134",
    "CVE-2024-50141",
    "CVE-2024-50142",
    "CVE-2024-50143",
    "CVE-2024-50150",
    "CVE-2024-50151",
    "CVE-2024-50153",
    "CVE-2024-50154",
    "CVE-2024-50162",
    "CVE-2024-50163",
    "CVE-2024-50182",
    "CVE-2024-50185",
    "CVE-2024-50192",
    "CVE-2024-50194",
    "CVE-2024-50195",
    "CVE-2024-50199",
    "CVE-2024-50201",
    "CVE-2024-50229",
    "CVE-2024-50244",
    "CVE-2024-50245",
    "CVE-2024-50247",
    "CVE-2024-50249",
    "CVE-2024-50251",
    "CVE-2024-50257",
    "CVE-2024-50259",
    "CVE-2024-50262",
    "CVE-2024-50264",
    "CVE-2024-50273",
    "CVE-2024-50278",
    "CVE-2024-50279",
    "CVE-2024-50299",
    "CVE-2024-50301",
    "CVE-2024-50302",
    "CVE-2024-53042",
    "CVE-2024-53052",
    "CVE-2024-53057",
    "CVE-2024-53066",
    "CVE-2024-53095",
    "CVE-2024-53097",
    "CVE-2024-53103"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.15-2025-060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.15.173-118.169. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.15-2025-060 advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    drm/i915: Fix potential context UAFs (CVE-2023-52913)

    In the Linux kernel, the following vulnerability has been resolved:

    dm-crypt, dm-verity: disable tasklets (CVE-2024-26718)

    In the Linux kernel, the following vulnerability has been resolved:

    net: bridge: xmit: make sure we have at least eth header len bytes (CVE-2024-38538)

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring: fix possible deadlock in io_register_iowq_max_workers() (CVE-2024-41080)

    In the Linux kernel, the following vulnerability has been resolved:

    cifs: Fix buffer overflow when parsing NFS reparse points (CVE-2024-49996)

    In the Linux kernel, the following vulnerability has been resolved:

    exec: don't WARN for racy path_noexec check (CVE-2024-50010)

    In the Linux kernel, the following vulnerability has been resolved:

    net: do not delay dst_entries_add() in dst_release() (CVE-2024-50036)

    In the Linux kernel, the following vulnerability has been resolved:

    serial: protect uart_port_dtr_rts() in uart_shutdown() too (CVE-2024-50058)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/bugs: Use code segment selector for VERW operand (CVE-2024-50072)

    In the Linux kernel, the following vulnerability has been resolved:

    blk-rq-qos: fix crash on rq_qos_wait vs. rq_qos_wake_function race (CVE-2024-50082)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: fix mptcp DSS corruption due to large pmtu xmit (CVE-2024-50083)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: pm: fix UaF read in mptcp_pm_nl_rm_addr_or_subflow (CVE-2024-50085)

    In the Linux kernel, the following vulnerability has been resolved:

    arm64: probes: Remove broken LDR (literal) uprobe support (CVE-2024-50099)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu/vt-d: Fix incorrect pci_for_each_dma_alias() for non-PCI devices (CVE-2024-50101)

    In the Linux kernel, the following vulnerability has been resolved:

    xfrm: fix one more kernel-infoleak in algo dumping (CVE-2024-50110)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory (CVE-2024-50115)

    In the Linux kernel, the following vulnerability has been resolved:

    net: sched: fix use-after-free in taprio_change() (CVE-2024-50127)

    In the Linux kernel, the following vulnerability has been resolved:

    net: wwan: fix global oob in wwan_rtnl_policy (CVE-2024-50128)

    In the Linux kernel, the following vulnerability has been resolved:

    tracing: Consider the NULL character when validating the event length (CVE-2024-50131)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/vboxvideo: Replace fake VLA at end of vbva_mouse_pointer_shape with real VLA (CVE-2024-50134)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: PRM: Find EFI_MEMORY_RUNTIME block for PRM handler and context (CVE-2024-50141)

    In the Linux kernel, the following vulnerability has been resolved:

    xfrm: validate new SA's prefixlen using SA family when sel.family is unset (CVE-2024-50142)

    In the Linux kernel, the following vulnerability has been resolved:

    udf: fix uninit-value use in udf_get_fileshortad (CVE-2024-50143)

    In the Linux kernel, the following vulnerability has been resolved:

    usb: typec: altmode should keep reference to parent (CVE-2024-50150)

    In the Linux kernel, the following vulnerability has been resolved:

    smb: client: fix OOBs when building SMB2_IOCTL request (CVE-2024-50151)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: target: core: Fix null-ptr-deref in target_alloc_device() (CVE-2024-50153)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp/dccp: Don't use timer_pending() in reqsk_queue_unlink(). (CVE-2024-50154)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: devmap: provide rxq after redirect (CVE-2024-50162)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Make sure internal and UAPI bpf_redirect flags don't overlap (CVE-2024-50163)

    In the Linux kernel, the following vulnerability has been resolved:

    secretmem: disable memfd_secret() if arch cannot set direct map (CVE-2024-50182)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: handle consistently DSS corruption (CVE-2024-50185)

    In the Linux kernel, the following vulnerability has been resolved:

    irqchip/gic-v4: Don't allow a VMOVP on a dying VPE (CVE-2024-50192)

    In the Linux kernel, the following vulnerability has been resolved:

    arm64: probes: Fix uprobes for big-endian kernels (CVE-2024-50194)

    In the Linux kernel, the following vulnerability has been resolved:

    posix-clock: Fix missing timespec64 check in pc_clock_settime() (CVE-2024-50195)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/swapfile: skip HugeTLB pages for unuse_vma (CVE-2024-50199)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/radeon: Fix encoder->possible_clones (CVE-2024-50201)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix potential deadlock with newly created symlinks (CVE-2024-50229)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/ntfs3: Additional check in ni_clear() (CVE-2024-50244)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/ntfs3: Fix possible deadlock in mi_read (CVE-2024-50245)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/ntfs3: Check if more than chunk-size bytes are written (CVE-2024-50247)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: CPPC: Make rmw_lock a raw_spin_lock (CVE-2024-50249)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_payload: sanitize offset and length before calling skb_checksum() (CVE-2024-50251)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: Fix use-after-free in get_info() (CVE-2024-50257)

    In the Linux kernel, the following vulnerability has been resolved:

    netdevsim: Add trailing zero to terminate the string in nsim_nexthop_bucket_activity_write()
    (CVE-2024-50259)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Fix out-of-bounds write in trie_get_next_key() (CVE-2024-50262)

    In the Linux kernel, the following vulnerability has been resolved:

    vsock/virtio: Initialization of the dangling pointer occurring in vsk->trans (CVE-2024-50264)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: reinitialize delayed ref list after deleting it from the list (CVE-2024-50273)

    In the Linux kernel, the following vulnerability has been resolved:

    dm cache: fix potential out-of-bounds access on the first resume (CVE-2024-50278)

    In the Linux kernel, the following vulnerability has been resolved:

    dm cache: fix out-of-bounds access to the dirty bitset when resizing (CVE-2024-50279)

    In the Linux kernel, the following vulnerability has been resolved:

    sctp: properly validate chunk size in sctp_sf_ootb() (CVE-2024-50299)

    In the Linux kernel, the following vulnerability has been resolved:

    security/keys: fix slab-out-of-bounds in key_task_permission (CVE-2024-50301)

    In the Linux kernel, the following vulnerability has been resolved: HID: core: zero-initialize the report
    buffer Since the report buffer is used by all kinds of drivers in various ways, let's zero-initialize it
    during allocation to make sure that it can't be ever used to leak kernel memory via specially-crafted
    report. (CVE-2024-50302)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv4: ip_tunnel: Fix suspicious RCU usage warning in ip_tunnel_init_flow() (CVE-2024-53042)

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring/rw: fix missing NOWAIT check for O_DIRECT start write (CVE-2024-53052)

    In the Linux kernel, the following vulnerability has been resolved:

    net/sched: stop qdisc_tree_reduce_backlog on TC_H_ROOT (CVE-2024-53057)

    In the Linux kernel, the following vulnerability has been resolved:

    nfs: Fix KMSAN warning in decode_getfattr_attrs() (CVE-2024-53066)

    In the Linux kernel, the following vulnerability has been resolved:

    smb: client: Fix use-after-free of network namespace. (CVE-2024-53095)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: krealloc: Fix MTE false alarm in __do_krealloc (CVE-2024-53097)

    In the Linux kernel, the following vulnerability has been resolved:

    hv_sock: Initializing vsk->trans to NULL to prevent a dangling pointer (CVE-2024-53103)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.15-2025-060.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52913.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26718.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-38538.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-41080.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49996.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50010.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50036.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50058.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50072.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50082.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50083.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50085.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50099.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50101.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50110.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50115.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50127.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50128.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50131.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50134.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50141.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50142.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50143.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50150.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50151.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50153.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50154.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50162.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50163.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50182.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50185.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50192.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50194.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50195.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50199.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50201.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50229.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50244.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50245.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50247.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50249.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50251.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50257.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50259.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50262.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50264.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50273.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50278.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50279.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50299.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50301.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50302.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53042.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53052.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53057.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53066.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53095.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53097.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53103.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53103");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-5.15.173-118.169");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "kpatch.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");
include("hotfixes.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2023-52913", "CVE-2024-26718", "CVE-2024-38538", "CVE-2024-41080", "CVE-2024-49996", "CVE-2024-50010", "CVE-2024-50036", "CVE-2024-50058", "CVE-2024-50072", "CVE-2024-50082", "CVE-2024-50083", "CVE-2024-50085", "CVE-2024-50099", "CVE-2024-50101", "CVE-2024-50110", "CVE-2024-50115", "CVE-2024-50127", "CVE-2024-50128", "CVE-2024-50131", "CVE-2024-50134", "CVE-2024-50141", "CVE-2024-50142", "CVE-2024-50143", "CVE-2024-50150", "CVE-2024-50151", "CVE-2024-50153", "CVE-2024-50154", "CVE-2024-50162", "CVE-2024-50163", "CVE-2024-50182", "CVE-2024-50185", "CVE-2024-50192", "CVE-2024-50194", "CVE-2024-50195", "CVE-2024-50199", "CVE-2024-50201", "CVE-2024-50229", "CVE-2024-50244", "CVE-2024-50245", "CVE-2024-50247", "CVE-2024-50249", "CVE-2024-50251", "CVE-2024-50257", "CVE-2024-50259", "CVE-2024-50262", "CVE-2024-50264", "CVE-2024-50273", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50299", "CVE-2024-50301", "CVE-2024-50302", "CVE-2024-53042", "CVE-2024-53052", "CVE-2024-53057", "CVE-2024-53066", "CVE-2024-53095", "CVE-2024-53097", "CVE-2024-53103");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.15-2025-060");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-kernel-5.15"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'bpftool-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-debuginfo-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-debuginfo-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-common-aarch64-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-common-x86_64-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-devel-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-devel-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.173-118.169.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-livepatch-5.15.173-118.169-1.0-0.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-livepatch-5.15.173-118.169-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-debuginfo-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-debuginfo-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-devel-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-devel-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-debuginfo-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-debuginfo-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-debuginfo-5.15.173-118.169.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-debuginfo-5.15.173-118.169.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / etc");
}
