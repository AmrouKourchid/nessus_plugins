#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.10-2025-078.
##

include('compat.inc');

if (description)
{
  script_id(214623);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2024-38538",
    "CVE-2024-41080",
    "CVE-2024-47674",
    "CVE-2024-49996",
    "CVE-2024-50010",
    "CVE-2024-50036",
    "CVE-2024-50058",
    "CVE-2024-50072",
    "CVE-2024-50115",
    "CVE-2024-50116",
    "CVE-2024-50127",
    "CVE-2024-50131",
    "CVE-2024-50134",
    "CVE-2024-50142",
    "CVE-2024-50150",
    "CVE-2024-50151",
    "CVE-2024-50153",
    "CVE-2024-50194",
    "CVE-2024-50210",
    "CVE-2024-50229",
    "CVE-2024-50230",
    "CVE-2024-50251",
    "CVE-2024-50262",
    "CVE-2024-50264",
    "CVE-2024-50267",
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

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.10-2025-078)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.10.230-223.885. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.10-2025-078 advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    net: bridge: xmit: make sure we have at least eth header len bytes (CVE-2024-38538)

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring: fix possible deadlock in io_register_iowq_max_workers() (CVE-2024-41080)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: avoid leaving partial pfn mappings around in error case (CVE-2024-47674)

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

    KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory (CVE-2024-50115)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix kernel bug due to missing clearing of buffer delay flag (CVE-2024-50116)

    In the Linux kernel, the following vulnerability has been resolved:

    net: sched: fix use-after-free in taprio_change() (CVE-2024-50127)

    In the Linux kernel, the following vulnerability has been resolved:

    tracing: Consider the NULL character when validating the event length (CVE-2024-50131)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/vboxvideo: Replace fake VLA at end of vbva_mouse_pointer_shape with real VLA (CVE-2024-50134)

    In the Linux kernel, the following vulnerability has been resolved:

    xfrm: validate new SA's prefixlen using SA family when sel.family is unset (CVE-2024-50142)

    In the Linux kernel, the following vulnerability has been resolved:

    usb: typec: altmode should keep reference to parent (CVE-2024-50150)

    In the Linux kernel, the following vulnerability has been resolved:

    smb: client: fix OOBs when building SMB2_IOCTL request (CVE-2024-50151)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: target: core: Fix null-ptr-deref in target_alloc_device() (CVE-2024-50153)

    In the Linux kernel, the following vulnerability has been resolved:

    arm64: probes: Fix uprobes for big-endian kernels (CVE-2024-50194)

    In the Linux kernel, the following vulnerability has been resolved:

    posix-clock: posix-clock: Fix unbalanced locking in pc_clock_settime() (CVE-2024-50210)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix potential deadlock with newly created symlinks (CVE-2024-50229)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix kernel bug due to missing clearing of checked flag (CVE-2024-50230)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_payload: sanitize offset and length before calling skb_checksum() (CVE-2024-50251)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Fix out-of-bounds write in trie_get_next_key() (CVE-2024-50262)

    In the Linux kernel, the following vulnerability has been resolved:

    vsock/virtio: Initialization of the dangling pointer occurring in vsk->trans (CVE-2024-50264)

    In the Linux kernel, the following vulnerability has been resolved:

    USB: serial: io_edgeport: fix use after free in debug printk (CVE-2024-50267)

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
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2025-078.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-38538.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-41080.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47674.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-49996.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50010.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50036.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50058.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50072.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50115.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50116.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50127.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50131.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50134.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50142.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50150.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50151.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50153.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50194.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50210.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50229.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50230.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50251.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50262.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50264.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50267.html");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-5.10.230-223.885");
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
  var cve_list = make_list("CVE-2024-38538", "CVE-2024-41080", "CVE-2024-47674", "CVE-2024-49996", "CVE-2024-50010", "CVE-2024-50036", "CVE-2024-50058", "CVE-2024-50072", "CVE-2024-50115", "CVE-2024-50116", "CVE-2024-50127", "CVE-2024-50131", "CVE-2024-50134", "CVE-2024-50142", "CVE-2024-50150", "CVE-2024-50151", "CVE-2024-50153", "CVE-2024-50194", "CVE-2024-50210", "CVE-2024-50229", "CVE-2024-50230", "CVE-2024-50251", "CVE-2024-50262", "CVE-2024-50264", "CVE-2024-50267", "CVE-2024-50273", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50299", "CVE-2024-50301", "CVE-2024-50302", "CVE-2024-53042", "CVE-2024-53052", "CVE-2024-53057", "CVE-2024-53066", "CVE-2024-53095", "CVE-2024-53097", "CVE-2024-53103");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.10-2025-078");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-kernel-5.10"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'bpftool-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-aarch64-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-x86_64-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.230-223.885.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-livepatch-5.10.230-223.885-1.0-0.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-livepatch-5.10.230-223.885-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.230-223.885.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.230-223.885.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'}
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
