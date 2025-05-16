#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2025-802.
##

include('compat.inc');

if (description)
{
  script_id(216951);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/15");

  script_cve_id(
    "CVE-2024-41080",
    "CVE-2024-49960",
    "CVE-2024-49974",
    "CVE-2024-49996",
    "CVE-2024-50012",
    "CVE-2024-50036",
    "CVE-2024-50067",
    "CVE-2024-50072",
    "CVE-2024-50229",
    "CVE-2024-50242",
    "CVE-2024-50243",
    "CVE-2024-50244",
    "CVE-2024-50245",
    "CVE-2024-50247",
    "CVE-2024-50249",
    "CVE-2024-50251",
    "CVE-2024-50256",
    "CVE-2024-50257",
    "CVE-2024-50259",
    "CVE-2024-50262",
    "CVE-2024-50264",
    "CVE-2024-50271",
    "CVE-2024-50272",
    "CVE-2024-50273",
    "CVE-2024-50278",
    "CVE-2024-50279",
    "CVE-2024-50280",
    "CVE-2024-50299",
    "CVE-2024-50301",
    "CVE-2024-50302",
    "CVE-2024-53042",
    "CVE-2024-53052",
    "CVE-2024-53057",
    "CVE-2024-53066",
    "CVE-2024-53082",
    "CVE-2024-53093",
    "CVE-2024-53095",
    "CVE-2024-53096",
    "CVE-2024-53097",
    "CVE-2024-53100",
    "CVE-2024-53103",
    "CVE-2024-53106",
    "CVE-2024-53113",
    "CVE-2024-53119",
    "CVE-2024-53121",
    "CVE-2024-53122",
    "CVE-2024-53123",
    "CVE-2024-53129",
    "CVE-2024-53130",
    "CVE-2024-53131",
    "CVE-2024-53135",
    "CVE-2024-53138",
    "CVE-2024-53140"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");

  script_name(english:"Amazon Linux 2023 : bpftool, kernel, kernel-devel (ALAS2023-2025-802)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2025-802 advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring: fix possible deadlock in io_register_iowq_max_workers() (CVE-2024-41080)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix timer use-after-free on failed mount (CVE-2024-49960)

    In the Linux kernel, the following vulnerability has been resolved:

    NFSD: Limit the number of concurrent async COPY operations (CVE-2024-49974)

    In the Linux kernel, the following vulnerability has been resolved:

    cifs: Fix buffer overflow when parsing NFS reparse points (CVE-2024-49996)

    In the Linux kernel, the following vulnerability has been resolved:

    cpufreq: Avoid a bad reference count on CPU node (CVE-2024-50012)

    In the Linux kernel, the following vulnerability has been resolved:

    net: do not delay dst_entries_add() in dst_release() (CVE-2024-50036)

    In the Linux kernel, the following vulnerability has been resolved:

    uprobe: avoid out-of-bounds memory access of fetching args (CVE-2024-50067)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/bugs: Use code segment selector for VERW operand (CVE-2024-50072)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix potential deadlock with newly created symlinks (CVE-2024-50229)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/ntfs3: Additional check in ntfs_file_release (CVE-2024-50242)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/ntfs3: Fix general protection fault in run_is_mapped_full (CVE-2024-50243)

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

    netfilter: nf_reject_ipv6: fix potential crash in nf_send_reset6() (CVE-2024-50256)

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

    signal: restore the override_rlimit logic (CVE-2024-50271)

    In the Linux kernel, the following vulnerability has been resolved:

    filemap: Fix bounds checking in filemap_read() (CVE-2024-50272)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: reinitialize delayed ref list after deleting it from the list (CVE-2024-50273)

    In the Linux kernel, the following vulnerability has been resolved:

    dm cache: fix potential out-of-bounds access on the first resume (CVE-2024-50278)

    In the Linux kernel, the following vulnerability has been resolved:

    dm cache: fix out-of-bounds access to the dirty bitset when resizing (CVE-2024-50279)

    In the Linux kernel, the following vulnerability has been resolved:

    dm cache: fix flushing uninitialized delayed_work on cache_ctr error (CVE-2024-50280)

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

    virtio_net: Add hash_key_length check (CVE-2024-53082)

    In the Linux kernel, the following vulnerability has been resolved:

    nvme-multipath: defer partition scanning (CVE-2024-53093)

    In the Linux kernel, the following vulnerability has been resolved:

    smb: client: Fix use-after-free of network namespace. (CVE-2024-53095)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: resolve faulty mmap_region() error path behaviour (CVE-2024-53096)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: krealloc: Fix MTE false alarm in __do_krealloc (CVE-2024-53097)

    In the Linux kernel, the following vulnerability has been resolved:

    nvme: tcp: avoid race between queue_lock lock and destroy (CVE-2024-53100)

    In the Linux kernel, the following vulnerability has been resolved:

    hv_sock: Initializing vsk->trans to NULL to prevent a dangling pointer (CVE-2024-53103)

    In the Linux kernel, the following vulnerability has been resolved:

    ima: fix buffer overrun in ima_eventdigest_init_common (CVE-2024-53106)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: fix NULL pointer dereference in alloc_pages_bulk_noprof (CVE-2024-53113)

    In the Linux kernel, the following vulnerability has been resolved:

    virtio/vsock: Fix accept_queue memory leak (CVE-2024-53119)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5: fs, lock FTE when checking if active (CVE-2024-53121)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: cope racing subflow creation in mptcp_rcv_space_adjust (CVE-2024-53122)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: error out earlier on disconnect (CVE-2024-53123)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/rockchip: vop: Fix a dereferenced before check warning (CVE-2024-53129)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix null-ptr-deref in block_dirty_buffer tracepoint (CVE-2024-53130)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix null-ptr-deref in block_touch_buffer tracepoint (CVE-2024-53131)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: VMX: Bury Intel PT virtualization (guest/host mode) behind CONFIG_BROKEN (CVE-2024-53135)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5e: kTLS, Fix incorrect page refcounting (CVE-2024-53138)

    In the Linux kernel, the following vulnerability has been resolved:

    netlink: terminate outstanding dump on socket close (CVE-2024-53140)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2025-802.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-41080.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49960.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49974.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49996.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50012.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50036.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50067.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50072.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50229.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50242.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50243.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50244.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50245.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50247.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50249.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50251.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50256.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50257.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50259.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50262.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50264.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50271.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50272.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50273.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50278.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50279.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50280.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50299.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50301.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50302.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53042.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53052.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53057.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53066.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53082.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53093.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53095.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53096.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53097.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53100.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53103.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53106.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53113.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53119.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53121.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53122.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53123.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53129.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53130.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53131.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53135.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53138.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53140.html");
  script_set_attribute(attribute:"solution", value:
"");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53103");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-libbpf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-libbpf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-libbpf-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-6.1.119-129.201");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-modules-extra-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
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
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2024-41080", "CVE-2024-49960", "CVE-2024-49974", "CVE-2024-49996", "CVE-2024-50012", "CVE-2024-50036", "CVE-2024-50067", "CVE-2024-50072", "CVE-2024-50229", "CVE-2024-50242", "CVE-2024-50243", "CVE-2024-50244", "CVE-2024-50245", "CVE-2024-50247", "CVE-2024-50249", "CVE-2024-50251", "CVE-2024-50256", "CVE-2024-50257", "CVE-2024-50259", "CVE-2024-50262", "CVE-2024-50264", "CVE-2024-50271", "CVE-2024-50272", "CVE-2024-50273", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50280", "CVE-2024-50299", "CVE-2024-50301", "CVE-2024-50302", "CVE-2024-53042", "CVE-2024-53052", "CVE-2024-53057", "CVE-2024-53066", "CVE-2024-53082", "CVE-2024-53093", "CVE-2024-53095", "CVE-2024-53096", "CVE-2024-53097", "CVE-2024-53100", "CVE-2024-53103", "CVE-2024-53106", "CVE-2024-53113", "CVE-2024-53119", "CVE-2024-53121", "CVE-2024-53122", "CVE-2024-53123", "CVE-2024-53129", "CVE-2024-53130", "CVE-2024-53131", "CVE-2024-53135", "CVE-2024-53138", "CVE-2024-53140");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS2023-2025-802");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var pkgs = [
    {'reference':'bpftool-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-aarch64-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.119-129.201-1.0-0.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.119-129.201-1.0-0.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.119-129.201.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.119-129.201.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / etc");
}
