#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-603.
##

include('compat.inc');

if (description)
{
  script_id(194486);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/27");

  script_cve_id(
    "CVE-2023-52620",
    "CVE-2023-52641",
    "CVE-2024-1627",
    "CVE-2024-26621",
    "CVE-2024-26659",
    "CVE-2024-26686",
    "CVE-2024-26735",
    "CVE-2024-26741",
    "CVE-2024-26742",
    "CVE-2024-26760",
    "CVE-2024-26763",
    "CVE-2024-26764",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26774",
    "CVE-2024-26780",
    "CVE-2024-26782",
    "CVE-2024-26789",
    "CVE-2024-26791",
    "CVE-2024-26792",
    "CVE-2024-26793",
    "CVE-2024-26798",
    "CVE-2024-26803",
    "CVE-2024-26804",
    "CVE-2024-26805",
    "CVE-2024-26832",
    "CVE-2024-26835",
    "CVE-2024-26840",
    "CVE-2024-26844",
    "CVE-2024-26845",
    "CVE-2024-26849",
    "CVE-2024-26851",
    "CVE-2024-26857",
    "CVE-2024-27023",
    "CVE-2024-27024",
    "CVE-2024-27404",
    "CVE-2024-27413",
    "CVE-2024-27415",
    "CVE-2024-27417",
    "CVE-2024-27431"
  );

  script_name(english:"Amazon Linux 2023 : bpftool, kernel, kernel-devel (ALAS2023-2024-603)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2024-603 advisory.

    2024-09-12: CVE-2024-27404 was added to this advisory.

    2024-09-12: CVE-2024-27431 was added to this advisory.

    2024-09-12: CVE-2024-27415 was added to this advisory.

    2024-09-12: CVE-2024-27413 was added to this advisory.

    2024-08-14: CVE-2024-26849 was added to this advisory.

    2024-08-14: CVE-2024-26742 was added to this advisory.

    2024-08-14: CVE-2024-26851 was added to this advisory.

    2024-08-14: CVE-2024-26686 was added to this advisory.

    2024-08-14: CVE-2024-26764 was added to this advisory.

    2024-08-14: CVE-2024-26798 was added to this advisory.

    2024-08-14: CVE-2024-26840 was added to this advisory.

    2024-08-14: CVE-2024-26659 was added to this advisory.

    2024-08-14: CVE-2024-26805 was added to this advisory.

    2024-08-14: CVE-2024-26835 was added to this advisory.

    2024-08-14: CVE-2024-26845 was added to this advisory.

    2024-08-14: CVE-2024-26741 was added to this advisory.

    2024-08-14: CVE-2024-26803 was added to this advisory.

    2024-08-14: CVE-2024-26789 was added to this advisory.

    2024-08-14: CVE-2024-27023 was added to this advisory.

    2024-08-14: CVE-2024-26857 was added to this advisory.

    2024-08-14: CVE-2023-52641 was added to this advisory.

    2024-08-14: CVE-2024-26774 was added to this advisory.

    2024-08-14: CVE-2024-26735 was added to this advisory.

    2024-08-14: CVE-2024-26760 was added to this advisory.

    2024-08-14: CVE-2024-26763 was added to this advisory.

    2024-08-14: CVE-2024-26772 was added to this advisory.

    2024-08-14: CVE-2024-26832 was added to this advisory.

    2024-08-14: CVE-2024-26844 was added to this advisory.

    2024-08-14: CVE-2024-26804 was added to this advisory.

    2024-08-14: CVE-2024-26793 was added to this advisory.

    2024-08-14: CVE-2024-26792 was added to this advisory.

    2024-08-14: CVE-2024-27024 was added to this advisory.

    2024-08-14: CVE-2024-26773 was added to this advisory.

    2024-08-14: CVE-2024-26791 was added to this advisory.

    2024-08-14: CVE-2024-26780 was added to this advisory.

    2024-07-03: CVE-2023-52620 was added to this advisory.

    2024-06-06: CVE-2024-26621 was added to this advisory.

    2024-06-06: CVE-2024-27417 was added to this advisory.

    2024-05-23: CVE-2024-26782 was added to this advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_tables: disallow timeout for anonymous sets (CVE-2023-52620)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/ntfs3: Add NULL ptr dereference checking at the end of attr_allocate_frame() (CVE-2023-52641)

    A vulnerability was discovered in the Linux kernel's IPv4 networking stack. Under certain conditions,
    MPTCP and NetLabel can be configured in a way that triggers a double free memory error in
    net/ipv4/af_inet.c:inet_sock_destruct(). This may lead to a system crash, denial of service, or potential
    arbitrary code execution. (CVE-2024-1627)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: huge_memory: don't force huge page alignment on 32 bit (CVE-2024-26621)

    In the Linux kernel, the following vulnerability has been resolved:

    xhci: handle isoc Babble and Buffer Overrun events properly (CVE-2024-26659)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/proc: do_task_stat: use sig->stats_lock to gather the threads/children stats (CVE-2024-26686)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: sr: fix possible use-after-free and null-ptr-deref (CVE-2024-26735)

    In the Linux kernel, the following vulnerability has been resolved:

    dccp/tcp: Unhash sk from ehash for tb2 alloc failure after check_estalblished(). (CVE-2024-26741)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: smartpqi: Fix disable_managed_interrupts (CVE-2024-26742)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: target: pscsi: Fix bio_put() for error case (CVE-2024-26760)

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

    af_unix: Fix task hung while purging oob_skb in GC. (CVE-2024-26780)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: fix double-free on socket dismantle (CVE-2024-26782)

    In the Linux kernel, the following vulnerability has been resolved:

    crypto: arm64/neonbs - fix out-of-bounds access on short input (CVE-2024-26789)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: dev-replace: properly validate device names (CVE-2024-26791)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: fix double free of anonymous device after snapshot creation failure (CVE-2024-26792)

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

    mm: zswap: fix missing folio cleanup in writeback race path (CVE-2024-26832)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_tables: set dormant flag on hook register failure (CVE-2024-26835)

    In the Linux kernel, the following vulnerability has been resolved:

    cachefiles: fix memory leak in cachefiles_add_cache() (CVE-2024-26840)

    In the Linux kernel, the following vulnerability has been resolved:

    block: Fix WARNING in _copy_from_iter (CVE-2024-26844)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: target: core: Add TMF to tmr_list handling (CVE-2024-26845)

    In the Linux kernel, the following vulnerability has been resolved:

    netlink: add nla be16/32 types to minlen array (CVE-2024-26849)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_conntrack_h323: Add protection for bmp length out of range (CVE-2024-26851)

    In the Linux kernel, the following vulnerability has been resolved:

    geneve: make sure to pull inner header in geneve_rx() (CVE-2024-26857)

    In the Linux kernel, the following vulnerability has been resolved:

    md: Fix missing release of 'active_io' for flush (CVE-2024-27023)

    In the Linux kernel, the following vulnerability has been resolved:

    net/rds: fix WARNING in rds_conn_connect_if_down (CVE-2024-27024)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: fix data races on remote_id (CVE-2024-27404)

    In the Linux kernel, the following vulnerability has been resolved:

    efi/capsule-loader: fix incorrect allocation size (CVE-2024-27413)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: bridge: confirm multicast packets before passing them up the stack (CVE-2024-27415)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: fix potential struct net leak in inet6_rtm_getaddr() (CVE-2024-27417)

    In the Linux kernel, the following vulnerability has been resolved:

    cpumap: Zero-initialise xdp_rxq_info struct before running XDP program (CVE-2024-27431)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-603.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52620.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52641.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-1627.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26621.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26659.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26686.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26735.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26741.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26742.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26760.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26763.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26764.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26772.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26773.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26774.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26780.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26782.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26789.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26791.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26792.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26793.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26798.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26803.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26804.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26805.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26832.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26835.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26840.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26844.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26845.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26849.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26851.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26857.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27023.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27024.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27404.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27413.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27415.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27417.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27431.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update kernel --releasever 2023.4.20240429' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27024");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-6.1.82-99.168");
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

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list("CVE-2023-52620", "CVE-2023-52641", "CVE-2024-1627", "CVE-2024-26621", "CVE-2024-26659", "CVE-2024-26686", "CVE-2024-26735", "CVE-2024-26741", "CVE-2024-26742", "CVE-2024-26760", "CVE-2024-26763", "CVE-2024-26764", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26774", "CVE-2024-26780", "CVE-2024-26782", "CVE-2024-26789", "CVE-2024-26791", "CVE-2024-26792", "CVE-2024-26793", "CVE-2024-26798", "CVE-2024-26803", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26832", "CVE-2024-26835", "CVE-2024-26840", "CVE-2024-26844", "CVE-2024-26845", "CVE-2024-26849", "CVE-2024-26851", "CVE-2024-26857", "CVE-2024-27023", "CVE-2024-27024", "CVE-2024-27404", "CVE-2024-27413", "CVE-2024-27415", "CVE-2024-27417", "CVE-2024-27431");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS2023-2024-603");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var pkgs = [
    {'reference':'bpftool-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-aarch64-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.82-99.168-1.0-0.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.82-99.168-1.0-0.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.82-99.168.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.82-99.168.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
