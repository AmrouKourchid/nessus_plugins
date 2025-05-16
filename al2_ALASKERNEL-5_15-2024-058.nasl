#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.15-2024-058.
##

include('compat.inc');

if (description)
{
  script_id(213366);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2023-52434",
    "CVE-2023-52620",
    "CVE-2023-52640",
    "CVE-2023-52641",
    "CVE-2024-0841",
    "CVE-2024-1627",
    "CVE-2024-26601",
    "CVE-2024-26603",
    "CVE-2024-26659",
    "CVE-2024-26688",
    "CVE-2024-26733",
    "CVE-2024-26735",
    "CVE-2024-26737",
    "CVE-2024-26750",
    "CVE-2024-26754",
    "CVE-2024-26763",
    "CVE-2024-26764",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26774",
    "CVE-2024-26782",
    "CVE-2024-26791",
    "CVE-2024-26793",
    "CVE-2024-26798",
    "CVE-2024-26803",
    "CVE-2024-26804",
    "CVE-2024-26805",
    "CVE-2024-26820",
    "CVE-2024-26835",
    "CVE-2024-26840",
    "CVE-2024-26843",
    "CVE-2024-26845",
    "CVE-2024-26851",
    "CVE-2024-26852",
    "CVE-2024-26857",
    "CVE-2024-27024",
    "CVE-2024-27403",
    "CVE-2024-27413",
    "CVE-2024-27414",
    "CVE-2024-27415",
    "CVE-2024-27417",
    "CVE-2024-27431"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.15-2024-058)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.15.152-100.162. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.15-2024-058 advisory.

    2025-01-21: CVE-2024-26851 was added to this advisory.

    2025-01-21: CVE-2024-26791 was added to this advisory.

    2025-01-21: CVE-2024-26804 was added to this advisory.

    2025-01-21: CVE-2024-0841 was added to this advisory.

    2025-01-21: CVE-2024-26603 was added to this advisory.

    2025-01-21: CVE-2024-26773 was added to this advisory.

    2025-01-21: CVE-2024-26803 was added to this advisory.

    2025-01-21: CVE-2024-26840 was added to this advisory.

    2025-01-21: CVE-2024-27415 was added to this advisory.

    2025-01-21: CVE-2023-52620 was added to this advisory.

    2025-01-21: CVE-2024-26764 was added to this advisory.

    2025-01-21: CVE-2023-52641 was added to this advisory.

    2025-01-21: CVE-2024-1627 was added to this advisory.

    2025-01-21: CVE-2024-26688 was added to this advisory.

    2025-01-21: CVE-2024-27024 was added to this advisory.

    2025-01-21: CVE-2024-26793 was added to this advisory.

    2025-01-21: CVE-2024-26805 was added to this advisory.

    2025-01-21: CVE-2024-27413 was added to this advisory.

    2025-01-21: CVE-2024-26735 was added to this advisory.

    2025-01-21: CVE-2024-26820 was added to this advisory.

    2025-01-21: CVE-2024-26601 was added to this advisory.

    2025-01-21: CVE-2024-26835 was added to this advisory.

    2025-01-21: CVE-2024-26772 was added to this advisory.

    2025-01-21: CVE-2023-52434 was added to this advisory.

    2025-01-21: CVE-2024-26750 was added to this advisory.

    2025-01-21: CVE-2024-26798 was added to this advisory.

    2025-01-21: CVE-2024-27417 was added to this advisory.

    2025-01-21: CVE-2024-27431 was added to this advisory.

    2025-01-21: CVE-2024-26763 was added to this advisory.

    2025-01-21: CVE-2024-26774 was added to this advisory.

    2025-01-21: CVE-2024-26845 was added to this advisory.

    2025-01-21: CVE-2024-26782 was added to this advisory.

    2025-01-21: CVE-2024-26857 was added to this advisory.

    2025-01-21: CVE-2024-26659 was added to this advisory.

    A flaw was found in the smb client in the Linux kernel. A potential out-of-bounds error was seen in the
    smb2_parse_contexts() function. Validate offsets and lengths before dereferencing create contexts in
    smb2_parse_contexts(). (CVE-2023-52434)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_tables: disallow timeout for anonymous sets (CVE-2023-52620)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/ntfs3: Fix oob in ntfs_listxattr (CVE-2023-52640)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/ntfs3: Add NULL ptr dereference checking at the end of attr_allocate_frame() (CVE-2023-52641)

    A null pointer dereference flaw was found in the hugetlbfs_fill_super function in the Linux kernel
    hugetlbfs (HugeTLB pages) functionality. This issue may allow a local user to crash the system or
    potentially escalate their privileges on the system. (CVE-2024-0841)

    A vulnerability was discovered in the Linux kernel's IPv4 networking stack. Under certain conditions,
    MPTCP and NetLabel can be configured in a way that triggers a double free memory error in
    net/ipv4/af_inet.c:inet_sock_destruct(). This may lead to a system crash, denial of service, or potential
    arbitrary code execution. (CVE-2024-1627)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: regenerate buddy after block freeing failed if under fc replay

    This mostly reverts commit 6bd97bf273bd (ext4: remove redundantmb_regenerate_buddy()) and reintroduces
    mb_regenerate_buddy(). Based oncode in mb_free_blocks(), fast commit replay can end up marking as
    freeblocks that are already marked as such. This causes corruption of thebuddy bitmap so we need to
    regenerate it in that case. (CVE-2024-26601)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/fpu: Stop relying on userspace for info to fault in xsave buffer

    Before this change, the expected size of the user space buffer wastaken from fx_sw->xstate_size.
    fx_sw->xstate_size can be changedfrom user-space, so it is possible construct a sigreturn frame where:

    * fx_sw->xstate_size is smaller than the size required by valid bits infx_sw->xfeatures.* user-space
    unmaps parts of the sigrame fpu buffer so that not all ofthe buffer required by xrstor is accessible.

    In this case, xrstor tries to restore and accesses the unmapped areawhich results in a fault. But
    fault_in_readable succeeds because buf +fx_sw->xstate_size is within the still mapped area, so it goes
    back andtries xrstor again. It will spin in this loop forever.

    Instead, fault in the maximum size which can be touched by XRSTOR (takenfrom fpstate->user_size).

    [ dhansen: tweak subject / changelog ] (CVE-2024-26603)

    In the Linux kernel, the following vulnerability has been resolved:

    xhci: handle isoc Babble and Buffer Overrun events properly (CVE-2024-26659)

    In the Linux kernel, the following vulnerability has been resolved:

    fs,hugetlb: fix NULL pointer dereference in hugetlbs_fill_super (CVE-2024-26688)

    In the Linux kernel, the following vulnerability has been resolved:

    arp: Prevent overflow in arp_req_get(). (CVE-2024-26733)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: sr: fix possible use-after-free and null-ptr-deref (CVE-2024-26735)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Fix racing between bpf_timer_cancel_and_free and bpf_timer_cancel (CVE-2024-26737)

    In the Linux kernel, the following vulnerability has been resolved:

    af_unix: Drop oob_skb ref before purging queue in GC. (CVE-2024-26750)

    In the Linux kernel, the following vulnerability has been resolved:

    gtp: fix use-after-free and null-ptr-deref in gtp_genl_dump_pdp() (CVE-2024-26754)

    In the Linux kernel, the following vulnerability has been resolved:

    dm-crypt: don't modify the data when using authenticated encryption (CVE-2024-26763)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/aio: Restrict kiocb_set_cancel_fn() to I/O submitted via libaio (CVE-2024-26764)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: avoid allocating blocks from corrupted group in ext4_mb_find_by_goal() (CVE-2024-26772)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: avoid allocating blocks from corrupted group in ext4_mb_try_best_found() (CVE-2024-26773)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: avoid dividing by 0 in mb_update_avg_fragment_size() when block bitmap corrupt (CVE-2024-26774)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: fix double-free on socket dismantle (CVE-2024-26782)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: dev-replace: properly validate device names (CVE-2024-26791)

    In the Linux kernel, the following vulnerability has been resolved:

    gtp: fix use-after-free and null-ptr-deref in gtp_newlink() (CVE-2024-26793)

    In the Linux kernel, the following vulnerability has been resolved:

    fbcon: always restore the old font data in fbcon_do_set_font() (CVE-2024-26798)

    In the Linux kernel, the following vulnerability has been resolved:

    net: veth: clear GRO when clearing XDP even when down (CVE-2024-26803)

    In the Linux kernel, the following vulnerability has been resolved:

    net: ip_tunnel: prevent perpetual headroom growth (CVE-2024-26804)

    In the Linux kernel, the following vulnerability has been resolved:

    netlink: Fix kernel-infoleak-after-free in __skb_datagram_iter (CVE-2024-26805)

    In the Linux kernel, the following vulnerability has been resolved:

    hv_netvsc: Register VF in netvsc_probe if NET_DEVICE_REGISTER missed (CVE-2024-26820)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_tables: set dormant flag on hook register failure (CVE-2024-26835)

    In the Linux kernel, the following vulnerability has been resolved:

    cachefiles: fix memory leak in cachefiles_add_cache() (CVE-2024-26840)

    In the Linux kernel, the following vulnerability has been resolved:

    efi: runtime: Fix potential overflow of soft-reserved region size (CVE-2024-26843)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: target: core: Add TMF to tmr_list handling (CVE-2024-26845)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_conntrack_h323: Add protection for bmp length out of range (CVE-2024-26851)

    In the Linux kernel, the following vulnerability has been resolved:

    net/ipv6: avoid possible UAF in ip6_route_mpath_notify() (CVE-2024-26852)

    In the Linux kernel, the following vulnerability has been resolved:

    geneve: make sure to pull inner header in geneve_rx() (CVE-2024-26857)

    In the Linux kernel, the following vulnerability has been resolved:

    net/rds: fix WARNING in rds_conn_connect_if_down (CVE-2024-27024)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_flow_offload: reset dst in route object after setting up flow (CVE-2024-27403)

    In the Linux kernel, the following vulnerability has been resolved:

    efi/capsule-loader: fix incorrect allocation size (CVE-2024-27413)

    In the Linux kernel, the following vulnerability has been resolved:

    rtnetlink: fix error logic of IFLA_BRIDGE_FLAGS writing back (CVE-2024-27414)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: bridge: confirm multicast packets before passing them up the stack (CVE-2024-27415)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: fix potential struct net leak in inet6_rtm_getaddr() (CVE-2024-27417)

    In the Linux kernel, the following vulnerability has been resolved:

    cpumap: Zero-initialise xdp_rxq_info struct before running XDP program (CVE-2024-27431)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.15-2024-058.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52434.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52620.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52640.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52641.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0841.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-1627.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26601.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26603.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26659.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26688.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26733.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26735.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26737.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26750.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26754.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26763.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26764.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26772.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26773.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26774.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26782.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26791.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26793.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26798.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26803.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26804.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26805.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26820.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26835.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26840.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26843.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26845.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26851.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26852.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26857.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27024.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27403.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27413.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27414.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27415.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27417.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27431.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52434");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-5.15.152-100.162");
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

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list("CVE-2023-52434", "CVE-2023-52620", "CVE-2023-52640", "CVE-2023-52641", "CVE-2024-0841", "CVE-2024-1627", "CVE-2024-26601", "CVE-2024-26603", "CVE-2024-26659", "CVE-2024-26688", "CVE-2024-26733", "CVE-2024-26735", "CVE-2024-26737", "CVE-2024-26750", "CVE-2024-26754", "CVE-2024-26763", "CVE-2024-26764", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26774", "CVE-2024-26782", "CVE-2024-26791", "CVE-2024-26793", "CVE-2024-26798", "CVE-2024-26803", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26820", "CVE-2024-26835", "CVE-2024-26840", "CVE-2024-26843", "CVE-2024-26845", "CVE-2024-26851", "CVE-2024-26852", "CVE-2024-26857", "CVE-2024-27024", "CVE-2024-27403", "CVE-2024-27413", "CVE-2024-27414", "CVE-2024-27415", "CVE-2024-27417", "CVE-2024-27431");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.15-2024-058");
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
    {'reference':'bpftool-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-debuginfo-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-debuginfo-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-common-aarch64-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-common-x86_64-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-devel-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-devel-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.152-100.162.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-livepatch-5.15.152-100.162-1.0-0.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-livepatch-5.15.152-100.162-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-debuginfo-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-debuginfo-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-devel-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-devel-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-debuginfo-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-debuginfo-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-debuginfo-5.15.152-100.162.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-debuginfo-5.15.152-100.162.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'}
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
