#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-643.
##

include('compat.inc');

if (description)
{
  script_id(200913);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2024-26900",
    "CVE-2024-35947",
    "CVE-2024-36017",
    "CVE-2024-36028",
    "CVE-2024-36882",
    "CVE-2024-36883",
    "CVE-2024-36889",
    "CVE-2024-36890",
    "CVE-2024-36896",
    "CVE-2024-36902",
    "CVE-2024-36904",
    "CVE-2024-36905",
    "CVE-2024-36912",
    "CVE-2024-36916",
    "CVE-2024-36917",
    "CVE-2024-36929",
    "CVE-2024-36933",
    "CVE-2024-36937",
    "CVE-2024-36938",
    "CVE-2024-36939",
    "CVE-2024-36940",
    "CVE-2024-36944",
    "CVE-2024-36959"
  );

  script_name(english:"Amazon Linux 2023 : bpftool, kernel, kernel-devel (ALAS2023-2024-643)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2024-643 advisory.

    In the Linux kernel, the following vulnerability has been resolved:

    md: fix kmemleak of rdev->serial (CVE-2024-26900)

    In the Linux kernel, the following vulnerability has been resolved:

    dyndbg: fix old BUG_ON in >control parser (CVE-2024-35947)

    In the Linux kernel, the following vulnerability has been resolved:

    rtnetlink: Correct nested IFLA_VF_VLAN_LIST attribute validation (CVE-2024-36017)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/hugetlb: fix DEBUG_LOCKS_WARN_ON(1) when dissolve_free_hugetlb_folio() (CVE-2024-36028)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: use memalloc_nofs_save() in page_cache_ra_order() (CVE-2024-36882)

    In the Linux kernel, the following vulnerability has been resolved:

    net: fix out-of-bounds access in ops_init (CVE-2024-36883)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: ensure snd_nxt is properly initialized on connect (CVE-2024-36889)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/slab: make __free(kfree) accept error pointers (CVE-2024-36890)

    In the Linux kernel, the following vulnerability has been resolved:

    USB: core: Fix access violation during port device removal (CVE-2024-36896)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: fib6_rules: avoid possible NULL dereference in fib6_rule_action() (CVE-2024-36902)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: Use refcount_inc_not_zero() in tcp_twsk_unique(). (CVE-2024-36904)

    In the Linux kernel, the following vulnerability has been resolved:

    tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets (CVE-2024-36905)

    In the Linux kernel, the following vulnerability has been resolved:

    Drivers: hv: vmbus: Track decrypted status in vmbus_gpadl (CVE-2024-36912)

    In the Linux kernel, the following vulnerability has been resolved:

    blk-iocost: avoid out of bounds shift (CVE-2024-36916)

    In the Linux kernel, the following vulnerability has been resolved:

    block: fix overflow in blk_ioctl_discard() (CVE-2024-36917)

    In the Linux kernel, the following vulnerability has been resolved:

    net: core: reject skb_copy(_expand) for fraglist GSO skbs (CVE-2024-36929)

    In the Linux kernel, the following vulnerability has been resolved:

    nsh: Restore skb->{protocol,data,mac_header} for outer header in nsh_gso_segment(). (CVE-2024-36933)

    In the Linux kernel, the following vulnerability has been resolved:

    xdp: use flags field to disambiguate broadcast redirect (CVE-2024-36937)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf, skmsg: Fix NULL pointer dereference in sk_psock_skb_ingress_enqueue (CVE-2024-36938)

    In the Linux kernel, the following vulnerability has been resolved:

    nfs: Handle error of rpc_proc_register() in nfs_net_init(). (CVE-2024-36939)

    In the Linux kernel, the following vulnerability has been resolved:

    pinctrl: core: delete incorrect free in pinctrl_enable() (CVE-2024-36940)

    In the Linux kernel, the following vulnerability has been resolved:

    Reapply drm/qxl: simplify qxl_fence_wait (CVE-2024-36944)

    In the Linux kernel, the following vulnerability has been resolved:

    pinctrl: devicetree: fix refcount leak in pinctrl_dt_to_map() (CVE-2024-36959)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-643.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26900.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35947.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36017.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36028.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36882.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36883.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36889.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36890.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36896.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36902.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36904.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36905.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36912.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36916.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36917.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36929.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36933.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36937.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36938.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36939.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36940.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36944.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36959.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update kernel --releasever 2023.5.20240624' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36940");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/24");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-6.1.91-99.172");
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
  var cve_list = make_list("CVE-2024-26900", "CVE-2024-35947", "CVE-2024-36017", "CVE-2024-36028", "CVE-2024-36882", "CVE-2024-36883", "CVE-2024-36889", "CVE-2024-36890", "CVE-2024-36896", "CVE-2024-36902", "CVE-2024-36904", "CVE-2024-36905", "CVE-2024-36912", "CVE-2024-36916", "CVE-2024-36917", "CVE-2024-36929", "CVE-2024-36933", "CVE-2024-36937", "CVE-2024-36938", "CVE-2024-36939", "CVE-2024-36940", "CVE-2024-36944", "CVE-2024-36959");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS2023-2024-643");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var pkgs = [
    {'reference':'bpftool-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-aarch64-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.91-99.172-1.0-0.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.91-99.172-1.0-0.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.91-99.172.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.91-99.172.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
