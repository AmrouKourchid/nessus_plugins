##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.10-2022-001.
##

include('compat.inc');

if (description)
{
  script_id(160443);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2020-25673",
    "CVE-2021-3489",
    "CVE-2021-3490",
    "CVE-2021-3491",
    "CVE-2021-3501",
    "CVE-2021-46904",
    "CVE-2021-46905",
    "CVE-2021-46908",
    "CVE-2021-46909",
    "CVE-2021-46912",
    "CVE-2021-46914",
    "CVE-2021-46915",
    "CVE-2021-46922",
    "CVE-2021-46971",
    "CVE-2021-46972",
    "CVE-2021-46974",
    "CVE-2021-23133",
    "CVE-2021-29155",
    "CVE-2021-31829"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.10-2022-001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.10.35-31.135. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.10-2022-001 advisory.

    2024-05-23: CVE-2021-46972 was added to this advisory.

    2024-05-23: CVE-2021-46974 was added to this advisory.

    2024-05-23: CVE-2021-46909 was added to this advisory.

    2024-04-25: CVE-2021-46922 was added to this advisory.

    2024-04-25: CVE-2021-46912 was added to this advisory.

    2024-04-25: CVE-2021-46908 was added to this advisory.

    2024-04-25: CVE-2021-46914 was added to this advisory.

    2024-04-25: CVE-2021-46971 was added to this advisory.

    2024-03-13: CVE-2021-46915 was added to this advisory.

    2024-03-13: CVE-2021-46904 was added to this advisory.

    2024-03-13: CVE-2021-46905 was added to this advisory.

    A use-after-free flaw was found in the Linux kernel's NFC LLCP protocol implementation in the way the user
    performs manipulation with an unknown input for the llcp_sock_bind() function. This flaw allows a local
    user to crash or escalate their privileges on the system. (CVE-2020-25670)

    A use-after-free flaw was found in the Linux kernel's NFC LLCP protocol implementation in the way the user
    triggers the llcp_sock_connect() function. This flaw allows a local user to crash the system.
    (CVE-2020-25671)

    A memory leak in the Linux kernel's NFC LLCP protocol implementation was found in the way a user triggers
    the llcp_sock_connect() function. This flaw allows a local user to starve the resources, causing a denial
    of service. (CVE-2020-25672)

    A vulnerability was found in Linux kernel where non-blocking socket in llcp_sock_connect() leads to leak
    and eventually hanging-up the system. (CVE-2020-25673)

    A use-after-free flaw was found in the Linux kernel's SCTP socket functionality that triggers a race
    condition. This flaw allows a local user to escalate their privileges on the system. The highest threat
    from this vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2021-23133)

    A vulnerability was discovered in retrieve_ptr_limit in kernel/bpf/verifier.c in the Linux kernel
    mechanism to mitigate speculatively out-of-bounds loads (Spectre mitigation). In this flaw a local,
    special user privileged (CAP_SYS_ADMIN) BPF program running on affected systems may bypass the protection,
    and execute speculatively out-of-bounds loads from the kernel memory. This can be abused to extract
    contents of kernel memory via side-channel. (CVE-2021-29155)

    A flaw was found in the Linux kernel's eBPF verification code. By default, accessing the eBPF verifier is
    only accessible to privileged users with CAP_SYS_ADMIN. This flaw allows a local user who can insert eBPF
    instructions, to use the eBPF verifier to abuse a spectre-like flaw and infer all system memory. The
    highest threat from this vulnerability is to confidentiality. (CVE-2021-31829)

    The eBPF RINGBUF bpf_ringbuf_reserve() function in the Linux kernel did not check that the allocated size
    was smaller than the ringbuf size, allowing an attacker to perform out-of-bounds writes within the kernel
    and therefore, arbitrary code execution. This issue was fixed via commit 4b81ccebaeee (bpf, ringbuf: Deny
    reserve of buffers larger than ringbuf) (v5.13-rc4) and backported to the stable kernels in v5.12.4,
    v5.11.21, and v5.10.37. It was introduced via 457f44363a88 (bpf: Implement BPF ring buffer and verifier
    support for it) (v5.8-rc1). (CVE-2021-3489)

    The eBPF ALU32 bounds tracking for bitwise ops (AND, OR and XOR) in the Linux kernel did not properly
    update 32-bit bounds, which could be turned into out of bounds reads and writes in the Linux kernel and
    therefore, arbitrary code execution. This issue was fixed via commit 049c4e13714e (bpf: Fix alu32 const
    subreg bound tracking on bitwise operations) (v5.13-rc4) and backported to the stable kernels in v5.12.4,
    v5.11.21, and v5.10.37. The AND/OR issues were introduced by commit 3f50f132d840 (bpf: Verifier, do
    explicit ALU32 bounds tracking) (5.7-rc1) and the XOR variant was introduced by 2921c90d4718 (bpf:Fix a
    verifier failure with xor) ( 5.10-rc1). (CVE-2021-3490)

    A flaw was found in the Linux kernel.  The io_uring PROVIDE_BUFFERS operation allowed the MAX_RW_COUNT
    limit to be bypassed, which led to negative values being used in mem_rw when reading /proc/<PID>/mem. The
    highest threat from this vulnerability is to data confidentiality and integrity as well as system
    availability. (CVE-2021-3491)

    A flaw was found in the Linux kernel in versions before 5.12. The value of internal.ndata, in the KVM API,
    is mapped to an array index, which can be updated by a user process at anytime which could lead to an out-
    of-bounds write. The highest threat from this vulnerability is to data integrity and system availability.
    (CVE-2021-3501)

    In the Linux kernel, the following vulnerability has been resolved:

    net: hso: fix null-ptr-deref during tty device unregistration

    Multiple ttys try to claim the same the minor number causing a doubleunregistration of the same device.
    The first unregistration succeedsbut the next one results in a null-ptr-deref.

    The get_free_serial_index() function returns an available minor numberbut doesn't assign it immediately.
    The assignment is done by the callerlater. But before this assignment, calls to
    get_free_serial_index()would return the same minor number.

    Fix this by modifying get_free_serial_index to assign the minor numberimmediately after one is found to be
    and rename it to obtain_minor()to better reflect what it does. Similary, rename set_serial_by_index()to
    release_minor() and modify it to free up the minor number of thegiven hso_serial. Every obtain_minor()
    should have correspondingrelease_minor() call. (CVE-2021-46904)

    In the Linux kernel, the following vulnerability has been resolved:

    net: hso: fix NULL-deref on disconnect regression

    Commit 8a12f8836145 (net: hso: fix null-ptr-deref during tty deviceunregistration) fixed the racy minor
    allocation reported by syzbot, butintroduced an unconditional NULL-pointer dereference on every
    disconnectinstead.

    Specifically, the serial device table must no longer be accessed afterthe minor has been released by
    hso_serial_tty_unregister(). (CVE-2021-46905)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Use correct permission flag for mixed signed bounds arithmetic

    We forbid adding unknown scalars with mixed signed bounds due to thespectre v1 masking mitigation. Hence
    this also needs bypass_spec_v1flag instead of allow_ptr_leaks. (CVE-2021-46908)

    In the Linux kernel, the following vulnerability has been resolved:

    ARM: footbridge: fix PCI interrupt mapping (CVE-2021-46909)

    In the Linux kernel, the following vulnerability has been resolved:

    net: Make tcp_allowed_congestion_control readonly in non-init netns (CVE-2021-46912)

    In the Linux kernel, the following vulnerability has been resolved:

    ixgbe: fix unbalanced device enable/disable in suspend/resume (CVE-2021-46914)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_limit: avoid possible divide error in nft_limit_init

    div_u64() divides u64 by u32.

    nft_limit_init() wants to divide u64 by u64, use the appropriatemath function (div64_u64)

    divide error: 0000 [#1] PREEMPT SMP KASANCPU: 1 PID: 8390 Comm: syz-executor188 Not tainted
    5.12.0-rc4-syzkaller #0Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google
    01/01/2011RIP: 0010:div_u64_rem include/linux/math64.h:28 [inline]RIP: 0010:div_u64
    include/linux/math64.h:127 [inline]RIP: 0010:nft_limit_init+0x2a2/0x5e0 net/netfilter/nft_limit.c:85Code:
    ef 4c 01 eb 41 0f 92 c7 48 89 de e8 38 a5 22 fa 4d 85 ff 0f 85 97 02 00 00 e8 ea 9e 22 fa 4c 0f af f3 45
    89 ed 31 d2 4c 89 f0 <49> f7 f5 49 89 c6 e8 d3 9e 22 fa 48 8d 7d 48 48 b8 00 00 00 00 00RSP:
    0018:ffffc90009447198 EFLAGS: 00010246RAX: 0000000000000000 RBX: 0000200000000000 RCX:
    0000000000000000RDX: 0000000000000000 RSI: ffffffff875152e6 RDI: 0000000000000003RBP: ffff888020f80908
    R08: 0000200000000000 R09: 0000000000000000R10: ffffffff875152d8 R11: 0000000000000000 R12:
    ffffc90009447270R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000FS:
    000000000097a300(0000) GS:ffff8880b9d00000(0000) knlGS:0000000000000000CS:  0010 DS: 0000 ES: 0000 CR0:
    0000000080050033CR2: 00000000200001c4 CR3: 0000000026a52000 CR4: 00000000001506e0DR0: 0000000000000000
    DR1: 0000000000000000 DR2: 0000000000000000DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
    0000000000000400Call Trace:nf_tables_newexpr net/netfilter/nf_tables_api.c:2675
    [inline]nft_expr_init+0x145/0x2d0 net/netfilter/nf_tables_api.c:2713nft_set_elem_expr_alloc+0x27/0x280
    net/netfilter/nf_tables_api.c:5160nf_tables_newset+0x1997/0x3150
    net/netfilter/nf_tables_api.c:4321nfnetlink_rcv_batch+0x85a/0x21b0
    net/netfilter/nfnetlink.c:456nfnetlink_rcv_skb_batch net/netfilter/nfnetlink.c:580
    [inline]nfnetlink_rcv+0x3af/0x420 net/netfilter/nfnetlink.c:598netlink_unicast_kernel
    net/netlink/af_netlink.c:1312 [inline]netlink_unicast+0x533/0x7d0
    net/netlink/af_netlink.c:1338netlink_sendmsg+0x856/0xd90 net/netlink/af_netlink.c:1927sock_sendmsg_nosec
    net/socket.c:654 [inline]sock_sendmsg+0xcf/0x120 net/socket.c:674____sys_sendmsg+0x6e8/0x810
    net/socket.c:2350___sys_sendmsg+0xf3/0x170 net/socket.c:2404__sys_sendmsg+0xe5/0x1b0
    net/socket.c:2433do_syscall_64+0x2d/0x70
    arch/x86/entry/common.c:46entry_SYSCALL_64_after_hwframe+0x44/0xae (CVE-2021-46915)

    In the Linux kernel, the following vulnerability has been resolved:

    KEYS: trusted: Fix TPM reservation for seal/unseal (CVE-2021-46922)

    In the Linux kernel, the following vulnerability has been resolved:

    perf/core: Fix unconditional security_locked_down() call (CVE-2021-46971)

    In the Linux kernel, the following vulnerability has been resolved:

    ovl: fix leaked dentry (CVE-2021-46972)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Fix masking negation logic upon negative dst register (CVE-2021-46974)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2022-001.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-25670.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-25671.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-25672.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-25673.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3489.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3490.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3491.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3501.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46904.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46905.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46908.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46909.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46912.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46914.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46915.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46922.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46971.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46972.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46974.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-23133.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-29155.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-31829.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3491");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux eBPF ALU32 32-bit Invalid Bounds Tracking LPE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
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

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kpatch.nasl", "ssh_get_info.nasl");
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
  var cve_list = make_list("CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-25673", "CVE-2021-3489", "CVE-2021-3490", "CVE-2021-3491", "CVE-2021-3501", "CVE-2021-23133", "CVE-2021-29155", "CVE-2021-31829", "CVE-2021-46904", "CVE-2021-46905", "CVE-2021-46908", "CVE-2021-46909", "CVE-2021-46912", "CVE-2021-46914", "CVE-2021-46915", "CVE-2021-46922", "CVE-2021-46971", "CVE-2021-46972", "CVE-2021-46974");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.10-2022-001");
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
    {'reference':'bpftool-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-aarch64-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-x86_64-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.35-31.135.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.35-31.135.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.35-31.135.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'}
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
      severity   : SECURITY_HOLE,
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
