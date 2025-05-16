#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2024-2549.
##

include('compat.inc');

if (description)
{
  script_id(198252);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2023-46838",
    "CVE-2023-52464",
    "CVE-2023-52470",
    "CVE-2023-52486",
    "CVE-2023-52583",
    "CVE-2023-52587",
    "CVE-2023-52612",
    "CVE-2023-52615",
    "CVE-2023-52619",
    "CVE-2023-52623",
    "CVE-2023-52675",
    "CVE-2023-52691",
    "CVE-2023-52698",
    "CVE-2024-0340",
    "CVE-2024-0607",
    "CVE-2024-26625",
    "CVE-2024-26633",
    "CVE-2024-26635",
    "CVE-2024-26663",
    "CVE-2024-26675",
    "CVE-2024-26679",
    "CVE-2024-26685",
    "CVE-2024-26696",
    "CVE-2024-26697",
    "CVE-2024-26704",
    "CVE-2024-26720",
    "CVE-2024-26735",
    "CVE-2024-26744",
    "CVE-2024-26752",
    "CVE-2024-26754",
    "CVE-2024-26763",
    "CVE-2024-26764",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26791",
    "CVE-2024-26793",
    "CVE-2024-26805",
    "CVE-2024-26816",
    "CVE-2024-26840",
    "CVE-2024-26845",
    "CVE-2024-26851",
    "CVE-2024-26857",
    "CVE-2024-26859",
    "CVE-2024-26863",
    "CVE-2024-26878",
    "CVE-2024-26880",
    "CVE-2024-26894",
    "CVE-2024-26898",
    "CVE-2024-26901",
    "CVE-2024-26917",
    "CVE-2024-26920",
    "CVE-2024-27388",
    "CVE-2024-27413",
    "CVE-2024-35835",
    "CVE-2024-50017"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALAS-2024-2549)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 4.14.343-259.562. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2024-2549 advisory.

    A flaw has been found in Xen. An unprivileged guest can cause Denial of Service (DoS) of the host by
    sending network packets to the backend, causing the backend to crash. (CVE-2023-46838)

    In the Linux kernel, the following vulnerability has been resolved:

    EDAC/thunderx: Fix possible out-of-bounds string access

    Enabling -Wstringop-overflow globally exposes a warning for a common bugin the usage of strncat():

    drivers/edac/thunderx_edac.c: In function
    'thunderx_ocx_com_threaded_isr':drivers/edac/thunderx_edac.c:1136:17: error: 'strncat' specified bound
    1024 equals destination size [-Werror=stringop-overflow=]1136 |                 strncat(msg, other,
    OCX_MESSAGE_SIZE);|                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~...1145 |
    strncat(msg, other, OCX_MESSAGE_SIZE);...1150 |                                 strncat(msg, other,
    OCX_MESSAGE_SIZE);

    ...

    Apparently the author of this driver expected strncat() to behave theway that strlcat() does, which uses
    the size of the destination bufferas its third argument rather than the length of the source buffer.
    Theresult is that there is no check on the size of the allocated buffer.

    Change it to strlcat().

    [ bp: Trim compiler output, fixup commit message. ] (CVE-2023-52464)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/radeon: check the alloc_workqueue return value in radeon_crtc_init()

    check the alloc_workqueue return value in radeon_crtc_init()to avoid null-ptr-deref. (CVE-2023-52470)

    In the Linux kernel, the following vulnerability has been resolved:

    drm: Don't unref the same fb many times by mistake due to deadlock handling (CVE-2023-52486)

    In the Linux kernel, the following vulnerability has been resolved:

    ceph: fix deadlock or deadcode of misusing dget() (CVE-2023-52583)

    In the Linux kernel, the following vulnerability has been resolved:

    IB/ipoib: Fix mcast list locking (CVE-2023-52587)

    In the Linux kernel, the following vulnerability has been resolved:

    crypto: scomp - fix req->dst buffer overflow (CVE-2023-52612)

    In the Linux kernel, the following vulnerability has been resolved:

    hwrng: core - Fix page fault dead lock on mmap-ed hwrng (CVE-2023-52615)

    In the Linux kernel, the following vulnerability has been resolved:

    pstore/ram: Fix crash when setting number of cpus to an odd number (CVE-2023-52619)

    In the Linux kernel, the following vulnerability has been resolved:

    SUNRPC: Fix a suspicious RCU usage warning (CVE-2023-52623)

    In the Linux kernel, the following vulnerability has been resolved:

    powerpc/imc-pmu: Add a null pointer check in update_events_in_group() (CVE-2023-52675)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/amd/pm: fix a double-free in si_dpm_init (CVE-2023-52691)

    In the Linux kernel, the following vulnerability has been resolved:

    calipso: fix memory leak in netlbl_calipso_add_pass() (CVE-2023-52698)

    A vulnerability was found in vhost_new_msg in drivers/vhost/vhost.c in the Linux kernel, which does not
    properly initialize memory in messages passed between virtual guests and the host operating system in the
    vhost/vhost.c:vhost_new_msg() function. This issue can allow local privileged users to read some kernel
    memory contents when reading from the /dev/vhost-net device file. (CVE-2024-0340)

    netfilter: nf_tables: fix pointer math issue in nft_byteorder_eval() (CVE-2024-0607)

    In the Linux kernel, the following vulnerability has been resolved:

    llc: call sock_orphan() at release time (CVE-2024-26625)

    In the Linux kernel, the following vulnerability has been resolved:

    ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim() (CVE-2024-26633)

    In the Linux kernel, the following vulnerability has been resolved:

    llc: Drop support for ETH_P_TR_802_2. (CVE-2024-26635)

    In the Linux kernel, the following vulnerability has been resolved:

    tipc: Check the bearer type before calling tipc_udp_nl_bearer_add() (CVE-2024-26663)

    In the Linux kernel, the following vulnerability has been resolved:

    ppp_async: limit MRU to 64K (CVE-2024-26675)

    In the Linux kernel, the following vulnerability has been resolved:

    inet: read sk->sk_family once in inet_recv_error() (CVE-2024-26679)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix potential bug in end_buffer_async_write (CVE-2024-26685)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix hang in nilfs_lookup_dirty_data_buffers() (CVE-2024-26696)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix data corruption in dsync block recovery for small block sizes (CVE-2024-26697)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix double-free of blocks due to wrong extents moved_len (CVE-2024-26704)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/writeback: fix possible divide-by-zero in wb_dirty_limits(), again (CVE-2024-26720)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: sr: fix possible use-after-free and null-ptr-deref (CVE-2024-26735)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/srpt: Support specifying the srpt_service_guid parameter (CVE-2024-26744)

    In the Linux kernel, the following vulnerability has been resolved:

    l2tp: pass correct message length to ip6_append_data (CVE-2024-26752)

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

    btrfs: dev-replace: properly validate device names (CVE-2024-26791)

    In the Linux kernel, the following vulnerability has been resolved:

    gtp: fix use-after-free and null-ptr-deref in gtp_newlink() (CVE-2024-26793)

    In the Linux kernel, the following vulnerability has been resolved:

    netlink: Fix kernel-infoleak-after-free in __skb_datagram_iter (CVE-2024-26805)

    In the Linux kernel, the following vulnerability has been resolved:

    x86, relocs: Ignore relocations in .notes section (CVE-2024-26816)

    In the Linux kernel, the following vulnerability has been resolved:

    cachefiles: fix memory leak in cachefiles_add_cache() (CVE-2024-26840)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: target: core: Add TMF to tmr_list handling (CVE-2024-26845)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nf_conntrack_h323: Add protection for bmp length out of range (CVE-2024-26851)

    In the Linux kernel, the following vulnerability has been resolved:

    geneve: make sure to pull inner header in geneve_rx() (CVE-2024-26857)

    In the Linux kernel, the following vulnerability has been resolved:

    net/bnx2x: Prevent access to a freed page in page_pool (CVE-2024-26859)

    In the Linux kernel, the following vulnerability has been resolved:

    hsr: Fix uninit-value access in hsr_get_node() (CVE-2024-26863)

    In the Linux kernel, the following vulnerability has been resolved:

    quota: Fix potential NULL pointer dereference (CVE-2024-26878)

    In the Linux kernel, the following vulnerability has been resolved:

    dm: call the resume method on internal suspend (CVE-2024-26880)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: processor_idle: Fix memory leak in acpi_processor_power_exit() (CVE-2024-26894)

    In the Linux kernel, the following vulnerability has been resolved:

    aoe: fix the potential use-after-free problem in aoecmd_cfg_pkts (CVE-2024-26898)

    In the Linux kernel, the following vulnerability has been resolved:

    do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak (CVE-2024-26901)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: Revert scsi: fcoe: Fix potential deadlock on &fip->ctlr_lock (CVE-2024-26917)

    In the Linux kernel, the following vulnerability has been resolved:

    tracing/trigger: Fix to return error if failed to alloc snapshot (CVE-2024-26920)

    In the Linux kernel, the following vulnerability has been resolved:

    SUNRPC: fix some memleaks in gssx_dec_option_array (CVE-2024-27388)

    In the Linux kernel, the following vulnerability has been resolved:

    efi/capsule-loader: fix incorrect allocation size (CVE-2024-27413)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5e: fix a double-free in arfs_create_groups (CVE-2024-35835)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/mm/ident_map: Use gbpages only where full GB page should be mapped. (CVE-2024-50017)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2024-2549.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-46838.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52464.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52470.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52486.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52583.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52587.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52612.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52615.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52619.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52623.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52675.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52691.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52698.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0340.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0607.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26625.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26633.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26635.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26663.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26675.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26679.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26685.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26696.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26697.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26704.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26720.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26735.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26744.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26752.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26754.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26763.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26764.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26772.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26773.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26791.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26793.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26805.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26816.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26840.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26845.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26851.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26857.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26859.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26863.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26878.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26880.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26894.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26898.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26901.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26917.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26920.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27388.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-27413.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35835.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-50017.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26898");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-4.14.343-259.562");
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
  var cve_list = make_list("CVE-2023-46838", "CVE-2023-52464", "CVE-2023-52470", "CVE-2023-52486", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52612", "CVE-2023-52615", "CVE-2023-52619", "CVE-2023-52623", "CVE-2023-52675", "CVE-2023-52691", "CVE-2023-52698", "CVE-2024-0340", "CVE-2024-0607", "CVE-2024-26625", "CVE-2024-26633", "CVE-2024-26635", "CVE-2024-26663", "CVE-2024-26675", "CVE-2024-26679", "CVE-2024-26685", "CVE-2024-26696", "CVE-2024-26697", "CVE-2024-26704", "CVE-2024-26720", "CVE-2024-26735", "CVE-2024-26744", "CVE-2024-26752", "CVE-2024-26754", "CVE-2024-26763", "CVE-2024-26764", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26791", "CVE-2024-26793", "CVE-2024-26805", "CVE-2024-26816", "CVE-2024-26840", "CVE-2024-26845", "CVE-2024-26851", "CVE-2024-26857", "CVE-2024-26859", "CVE-2024-26863", "CVE-2024-26878", "CVE-2024-26880", "CVE-2024-26894", "CVE-2024-26898", "CVE-2024-26901", "CVE-2024-26917", "CVE-2024-26920", "CVE-2024-27388", "CVE-2024-27413", "CVE-2024-35835", "CVE-2024-50017");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS-2024-2549");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var pkgs = [
    {'reference':'kernel-4.14.343-259.562.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.14.343-259.562.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-4.14.343-259.562.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-4.14.343-259.562.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-aarch64-4.14.343-259.562.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-4.14.343-259.562.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.343-259.562.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.343-259.562.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.343-259.562.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.343-259.562.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.343-259.562.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-4.14.343-259.562-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.343-259.562.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.343-259.562.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-4.14.343-259.562.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-4.14.343-259.562.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-4.14.343-259.562.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-4.14.343-259.562.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.343-259.562.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.343-259.562.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-4.14.343-259.562.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-4.14.343-259.562.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-4.14.343-259.562.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-4.14.343-259.562.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-debuginfo-4.14.343-259.562.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-debuginfo-4.14.343-259.562.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-x86_64 / etc");
}
