#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-517.
##

include('compat.inc');

if (description)
{
  script_id(190743);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/08");

  script_cve_id(
    "CVE-2023-52486",
    "CVE-2023-52489",
    "CVE-2023-52492",
    "CVE-2023-52498",
    "CVE-2023-52583",
    "CVE-2023-52614",
    "CVE-2023-52615",
    "CVE-2023-52619",
    "CVE-2023-52621",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2023-52672",
    "CVE-2024-1086",
    "CVE-2024-23849",
    "CVE-2024-26612",
    "CVE-2024-26614",
    "CVE-2024-26625",
    "CVE-2024-26626",
    "CVE-2024-26627",
    "CVE-2024-26634",
    "CVE-2024-26635",
    "CVE-2024-26638",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26644",
    "CVE-2024-26668",
    "CVE-2024-26671",
    "CVE-2024-26673",
    "CVE-2024-26808",
    "CVE-2024-26972"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/20");

  script_name(english:"Amazon Linux 2023 : bpftool, kernel, kernel-devel (ALAS2023-2024-517)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2024-517 advisory.

    2024-08-14: CVE-2023-52621 was added to this advisory.

    2024-08-14: CVE-2023-52623 was added to this advisory.

    2024-08-14: CVE-2024-26671 was added to this advisory.

    2024-08-14: CVE-2023-52622 was added to this advisory.

    2024-08-14: CVE-2024-26673 was added to this advisory.

    2024-08-14: CVE-2024-26644 was added to this advisory.

    2024-08-14: CVE-2024-26808 was added to this advisory.

    2024-08-01: CVE-2024-26972 was added to this advisory.

    2024-07-03: CVE-2023-52619 was added to this advisory.

    2024-07-03: CVE-2024-26626 was added to this advisory.

    2024-07-03: CVE-2024-26635 was added to this advisory.

    2024-07-03: CVE-2023-52614 was added to this advisory.

    2024-07-03: CVE-2023-52615 was added to this advisory.

    2024-07-03: CVE-2024-26640 was added to this advisory.

    2024-07-03: CVE-2024-26634 was added to this advisory.

    2024-07-03: CVE-2024-26641 was added to this advisory.

    2024-07-03: CVE-2024-26627 was added to this advisory.

    2024-07-03: CVE-2023-52583 was added to this advisory.

    2024-07-03: CVE-2024-26638 was added to this advisory.

    2024-06-06: CVE-2023-52498 was added to this advisory.

    2024-06-06: CVE-2023-52489 was added to this advisory.

    2024-06-06: CVE-2024-26614 was added to this advisory.

    2024-06-06: CVE-2023-52486 was added to this advisory.

    2024-06-06: CVE-2023-52672 was added to this advisory.

    2024-06-06: CVE-2024-26612 was added to this advisory.

    2024-06-06: CVE-2023-52492 was added to this advisory.

    2024-05-23: CVE-2024-26625 was added to this advisory.

    2024-05-23: CVE-2024-26668 was added to this advisory.

    2024-02-29: CVE-2024-1086 was added to this advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    drm: Don't unref the same fb many times by mistake due to deadlock handling (CVE-2023-52486)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/sparsemem: fix race in accessing memory_section->usage (CVE-2023-52489)

    In the Linux kernel, the following vulnerability has been resolved:

    dmaengine: fix NULL pointer in channel unregistration function (CVE-2023-52492)

    In the Linux kernel, the following vulnerability has been resolved:

    PM: sleep: Fix possible deadlocks in core system-wide PM code (CVE-2023-52498)

    In the Linux kernel, the following vulnerability has been resolved:

    ceph: fix deadlock or deadcode of misusing dget() (CVE-2023-52583)

    In the Linux kernel, the following vulnerability has been resolved:

    PM / devfreq: Fix buffer overflow in trans_stat_show (CVE-2023-52614)

    In the Linux kernel, the following vulnerability has been resolved:

    hwrng: core - Fix page fault dead lock on mmap-ed hwrng (CVE-2023-52615)

    In the Linux kernel, the following vulnerability has been resolved:

    pstore/ram: Fix crash when setting number of cpus to an odd number (CVE-2023-52619)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Check rcu_read_lock_trace_held() before calling bpf map helpers (CVE-2023-52621)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: avoid online resizing failures due to oversized flex bg (CVE-2023-52622)

    In the Linux kernel, the following vulnerability has been resolved:

    SUNRPC: Fix a suspicious RCU usage warning (CVE-2023-52623)

    In the Linux kernel, the following vulnerability has been resolved:

    pipe: wakeup wr_wait after setting max_usage (CVE-2023-52672)

    A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation.

    The nft_verdict_init() function allows positive values as drop error within the hook verdict, and hence
    the nf_hook_slow() function can cause a double free vulnerability when NF_DROP is issued with a drop error
    which resembles NF_ACCEPT.

    We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660. (CVE-2024-1086)

    In rds_recv_track_latency in net/rds/af_rds.c in the Linux kernel through 6.7.1, there is an off-by-one
    error for an RDS_MSG_RX_DGRAM_TRACE_MAX comparison, resulting in out-of-bounds access. (CVE-2024-23849)

    In the Linux kernel, the following vulnerability has been resolved:

    netfs, fscache: Prevent Oops in fscache_put_cache() (CVE-2024-26612)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: make sure init the accept_queue's spinlocks once (CVE-2024-26614)

    In the Linux kernel, the following vulnerability has been resolved:

    llc: call sock_orphan() at release time (CVE-2024-26625)

    In the Linux kernel, the following vulnerability has been resolved:

    ipmr: fix kernel panic when forwarding mcast packets (CVE-2024-26626)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: core: Move scsi_host_busy() out of host lock for waking up EH handler (CVE-2024-26627)

    In the Linux kernel, the following vulnerability has been resolved:

    net: fix removing a namespace with conflicting altnames (CVE-2024-26634)

    In the Linux kernel, the following vulnerability has been resolved:

    llc: Drop support for ETH_P_TR_802_2. (CVE-2024-26635)

    In the Linux kernel, the following vulnerability has been resolved:

    nbd: always initialize struct msghdr completely (CVE-2024-26638)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: add sanity checks to rx zerocopy (CVE-2024-26640)

    In the Linux kernel, the following vulnerability has been resolved:

    ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv() (CVE-2024-26641)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: don't abort filesystem when attempting to snapshot deleted subvolume (CVE-2024-26644)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_limit: reject configurations that cause integer overflow (CVE-2024-26668)

    In the Linux kernel, the following vulnerability has been resolved:

    blk-mq: fix IO hang from sbitmap wakeup race (CVE-2024-26671)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_ct: sanitize layer 3 and 4 protocol number in custom expectations (CVE-2024-26673)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_chain_filter: handle NETDEV_UNREGISTER for inet/ingress basechain (CVE-2024-26808)

    In the Linux kernel, the following vulnerability has been resolved:

    ubifs: ubifs_symlink: Fix memleak of inode->i_link in error path (CVE-2024-26972)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-517.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52486.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52489.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52492.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52498.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52583.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52614.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52615.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52619.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52621.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52622.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52623.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52672.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-1086.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-23849.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26612.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26614.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26625.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26626.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26627.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26634.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26635.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26638.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26640.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26641.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26644.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26668.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26671.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26673.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26808.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26972.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update kernel --releasever 2023.3.20240219' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26625");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-6.1.77-99.164");
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
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2023-52486", "CVE-2023-52489", "CVE-2023-52492", "CVE-2023-52498", "CVE-2023-52583", "CVE-2023-52614", "CVE-2023-52615", "CVE-2023-52619", "CVE-2023-52621", "CVE-2023-52622", "CVE-2023-52623", "CVE-2023-52672", "CVE-2024-1086", "CVE-2024-23849", "CVE-2024-26612", "CVE-2024-26614", "CVE-2024-26625", "CVE-2024-26626", "CVE-2024-26627", "CVE-2024-26634", "CVE-2024-26635", "CVE-2024-26638", "CVE-2024-26640", "CVE-2024-26641", "CVE-2024-26644", "CVE-2024-26668", "CVE-2024-26671", "CVE-2024-26673", "CVE-2024-26808", "CVE-2024-26972");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS2023-2024-517");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var pkgs = [
    {'reference':'bpftool-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-aarch64-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.77-99.164-1.0-0.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.77-99.164-1.0-0.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.77-99.164.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.77-99.164.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
