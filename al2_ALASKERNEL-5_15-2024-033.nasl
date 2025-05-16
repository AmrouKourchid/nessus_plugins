#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.15-2024-033.
##

include('compat.inc');

if (description)
{
  script_id(187777);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/17");

  script_cve_id(
    "CVE-2023-6121",
    "CVE-2023-6531",
    "CVE-2023-6622",
    "CVE-2023-6817",
    "CVE-2023-6931",
    "CVE-2023-6932",
    "CVE-2024-0584",
    "CVE-2024-0607",
    "CVE-2023-46862",
    "CVE-2023-52340",
    "CVE-2023-52654",
    "CVE-2023-52762",
    "CVE-2023-52772",
    "CVE-2023-52781",
    "CVE-2023-52784",
    "CVE-2023-52788",
    "CVE-2023-52791",
    "CVE-2023-52796",
    "CVE-2023-52803",
    "CVE-2023-52813",
    "CVE-2023-52828",
    "CVE-2023-52835",
    "CVE-2023-52881"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.15-2024-033)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.15.145-95.156. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.15-2024-033 advisory.

    2024-12-05: CVE-2023-52772 was added to this advisory.

    2024-12-05: CVE-2023-52835 was added to this advisory.

    2024-12-05: CVE-2023-52781 was added to this advisory.

    2024-12-05: CVE-2023-52828 was added to this advisory.

    2024-12-05: CVE-2023-52788 was added to this advisory.

    2024-12-05: CVE-2023-52791 was added to this advisory.

    2024-08-27: CVE-2023-52654 was added to this advisory.

    2024-07-03: CVE-2023-52813 was added to this advisory.

    2024-07-03: CVE-2023-52762 was added to this advisory.

    2024-06-19: CVE-2023-52784 was added to this advisory.

    2024-06-19: CVE-2023-52803 was added to this advisory.

    2024-06-19: CVE-2023-52796 was added to this advisory.

    2024-06-06: CVE-2023-52881 was added to this advisory.

    2024-06-06: CVE-2024-0607 was added to this advisory.

    2024-02-01: CVE-2024-0584 was added to this advisory.

    2024-01-19: CVE-2023-52340 was added to this advisory.

    2024-01-19: CVE-2023-6531 was added to this advisory.

    An issue was discovered in the Linux kernel through 6.5.9. During a race with SQ thread exit, an
    io_uring/fdinfo.c io_uring_show_fdinfo NULL pointer dereference can occur. (CVE-2023-46862)

    When a router encounters an IPv6 packet too big to transmit to the next-hop, it returns an ICMP6 Packet
    Too Big (PTB) message to the sender. The sender caches this updated Maximum Transmission Unit (MTU) so it
    knows not to exceed this value when subsequently routing to the same host.

    In Linux kernels prior to 6.3, garbage collection is run on the IPv6 Destination Route Cache if the number
    of entries exceeds a threshold when adding the destination to the cache. This garbage collection examines
    every entry in the cache while holding a lock. In these affected kernel versions, a flood of the IPv6
    ICMP6 PTB messages could cause high lock contention and increased CPU usage, leading to a Denial-of-
    Service.

    The fix backports the garbage collection improvements from Linux kernel 6.3 by bringing the IPv6 code
    closer to the IPv4 code, which does not have this issue.

    Patch: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit?id=af6d10345ca76670c1b7c3
    7799f0d5576ccef277 (CVE-2023-52340)

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring/af_unix: disable sending io_uring over sockets (CVE-2023-52654)

    In the Linux kernel, the following vulnerability has been resolved:

    virtio-blk: fix implicit overflow on virtio_max_dma_size (CVE-2023-52762)

    In the Linux kernel, the following vulnerability has been resolved:

    af_unix: fix use-after-free in unix_stream_read_actor() (CVE-2023-52772)

    In the Linux kernel, the following vulnerability has been resolved:

    usb: config: fix iteration issue in 'usb_get_bos_descriptor()' (CVE-2023-52781)

    In the Linux kernel, the following vulnerability has been resolved:

    bonding: stop the device in bond_setup_by_slave() (CVE-2023-52784)

    In the Linux kernel, the following vulnerability has been resolved:

    i915/perf: Fix NULL deref bugs with drm_dbg() calls (CVE-2023-52788)

    In the Linux kernel, the following vulnerability has been resolved:

    i2c: core: Run atomic i2c xfer when !preemptible (CVE-2023-52791)

    In the Linux kernel, the following vulnerability has been resolved:

    ipvlan: add ipvlan_route_v6_outbound() helper (CVE-2023-52796)

    In the Linux kernel, the following vulnerability has been resolved:

    SUNRPC: Fix RPC client cleaned up the freed pipefs dentries (CVE-2023-52803)

    In the Linux kernel, the following vulnerability has been resolved:

    crypto: pcrypt - Fix hungtask for PADATA_RESET (CVE-2023-52813)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Detect IP == ksym.end as part of BPF program (CVE-2023-52828)

    In the Linux kernel, the following vulnerability has been resolved:

    perf/core: Bail out early if the request AUX area is out of bound (CVE-2023-52835)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: do not accept ACK of bytes we never sent (CVE-2023-52881)

    An out-of-bounds read vulnerability was found in the NVMe-oF/TCP subsystem in the Linux kernel. This flaw
    allows a remote attacker to send a crafted TCP packet, triggering a heap-based buffer overflow that
    results in kmalloc data to be printed (and potentially leaked) to the kernel ring buffer (dmesg).
    (CVE-2023-6121)

    A use-after-free flaw was found in the Linux Kernel due to a race problem in the unix garbage collector's
    deletion of SKB races with unix_stream_read_generic() on the socket that the SKB is queued on.
    (CVE-2023-6531)

    A null pointer dereference vulnerability was found in nft_dynset_init() in net/netfilter/nft_dynset.c in
    nf_tables in the Linux kernel. This issue may allow a local attacker with CAP_NET_ADMIN user privilege to
    trigger a denial of service. (CVE-2023-6622)

    A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation.

    The function nft_pipapo_walk did not skip inactive elements during set walk which could lead double
    deactivations of PIPAPO (Pile Packet Policies) elements, leading to use-after-free.

    We recommend upgrading past commit 317eb9685095678f2c9f5a8189de698c5354316a. (CVE-2023-6817)

    A heap out-of-bounds write vulnerability in the Linux kernel's Performance Events system component can be
    exploited to achieve local privilege escalation.

    A perf_event's read_size can overflow, leading to an heap out-of-bounds increment or write in
    perf_read_group().

    We recommend upgrading past commit 382c27f4ed28f803b1f1473ac2d8db0afc795a1b. (CVE-2023-6931)

    A use-after-free vulnerability in the Linux kernel's ipv4: igmp component can be exploited to achieve
    local privilege escalation.

    A race condition can be exploited to cause a timer be mistakenly registered on a RCU read locked object
    which is freed by another thread.

    We recommend upgrading past commit e2b706c691905fe78468c361aaabc719d0a496f1. (CVE-2023-6932)

    A use-after-free issue was found in igmp_start_timer in net/ipv4/igmp.c in the network sub-component in
    the Linux Kernel. This flaw allows a local user to observe a refcnt use-after-free issue when receiving an
    igmp query packet, leading to a kernel information leak. (CVE-2024-0584)

    netfilter: nf_tables: fix pointer math issue in nft_byteorder_eval() (CVE-2024-0607)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.15-2024-033.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-6121.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-6531.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-6622.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-6817.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-6931.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-6932.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0584.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0607.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-46862.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52340.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52654.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52762.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52772.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52781.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52784.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52788.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52791.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52796.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52803.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52813.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52828.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52835.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52881.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6817");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-5.15.145-95.156");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2023-6121", "CVE-2023-6531", "CVE-2023-6622", "CVE-2023-6817", "CVE-2023-6931", "CVE-2023-6932", "CVE-2023-46862", "CVE-2023-52340", "CVE-2023-52654", "CVE-2023-52762", "CVE-2023-52772", "CVE-2023-52781", "CVE-2023-52784", "CVE-2023-52788", "CVE-2023-52791", "CVE-2023-52796", "CVE-2023-52803", "CVE-2023-52813", "CVE-2023-52828", "CVE-2023-52835", "CVE-2023-52881", "CVE-2024-0584", "CVE-2024-0607");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.15-2024-033");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}
var pkgs = [
    {'reference':'bpftool-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-debuginfo-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-debuginfo-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-common-aarch64-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-common-x86_64-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-devel-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-devel-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.145-95.156.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-livepatch-5.15.145-95.156-1.0-0.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-livepatch-5.15.145-95.156-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-debuginfo-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-debuginfo-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-devel-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-devel-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-debuginfo-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-debuginfo-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-debuginfo-5.15.145-95.156.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-debuginfo-5.15.145-95.156.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'}
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