##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.10-2022-009.
##

include('compat.inc');

if (description)
{
  script_id(160451);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/17");

  script_cve_id(
    "CVE-2021-4135",
    "CVE-2021-4155",
    "CVE-2021-28711",
    "CVE-2021-28712",
    "CVE-2021-28713",
    "CVE-2021-28714",
    "CVE-2021-28715",
    "CVE-2021-3923",
    "CVE-2021-43975",
    "CVE-2021-46929",
    "CVE-2021-46931",
    "CVE-2021-46934",
    "CVE-2021-46936",
    "CVE-2021-47090",
    "CVE-2021-47097",
    "CVE-2021-47505",
    "CVE-2021-47506",
    "CVE-2021-47507",
    "CVE-2021-47517",
    "CVE-2021-47538",
    "CVE-2021-47541",
    "CVE-2021-47542",
    "CVE-2021-47548",
    "CVE-2021-47550",
    "CVE-2021-47553",
    "CVE-2021-47560",
    "CVE-2021-47566",
    "CVE-2021-47576",
    "CVE-2021-47578",
    "CVE-2021-47579",
    "CVE-2021-47580",
    "CVE-2021-47584",
    "CVE-2021-47585",
    "CVE-2021-47588",
    "CVE-2021-47589",
    "CVE-2021-47593",
    "CVE-2021-47597",
    "CVE-2021-47598",
    "CVE-2021-47600",
    "CVE-2021-47603",
    "CVE-2021-47606",
    "CVE-2021-47609",
    "CVE-2022-0185"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/11");

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.10-2022-009)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.10.93-87.444. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.10-2022-009 advisory.

    A denial of service flaw for virtual machine guests in the Linux kernel's Xen hypervisor subsystem was
    found in the way users call some interrupts with high frequency from one of the guests.A local user could
    use this flaw to starve the resources resulting in a denial of service. (CVE-2021-28711)

    A denial of service flaw for virtual machine guests in the Linux kernel's Xen hypervisor subsystem was
    found in the way users call some interrupts with high frequency from one of the guests.A local user could
    use this flaw to starve the resources resulting in a denial of service. (CVE-2021-28712)

    A denial of service flaw for virtual machine guests in the Linux kernel's Xen hypervisor subsystem was
    found in the way users call some interrupts with high frequency from one of the guests.A local user could
    use this flaw to starve the resources resulting in a denial of service. (CVE-2021-28713)

    Incoming data packets for a guest in the Linux kernel's netback driver are buffered until the guest is
    ready to process them. There are some measures taken for avoiding to pile up too much data, but those can
    be bypassed by the guest: The timeout could even never trigger if the guest manages to have only one free
    slot in its RX queue ring page and the next package would require more than one free slot, which may be
    the case when using GSO, XDP, or software hashing. (CVE-2021-28714)

    Incoming data packets for a guest in the Linux kernel's netback driver are buffered until the guest is
    ready to process them. There are some measures taken for avoiding to pile up too much data, but those can
    be bypassed by the guest: There is a timeout how long the client side of an interface can stop consuming
    new packets before it is assumed to have stalled, but this timeout is rather long (60 seconds by default).
    Using a UDP connection on a fast interface can easily accumulate gigabytes of data in that time.
    (CVE-2021-28715)

    A flaw was found in the Linux kernel's implementation of RDMA over infiniband. An attacker with a
    privileged local account can leak kernel stack information when issuing commands to the
    /dev/infiniband/rdma_cm device node. While this access is unlikely to leak sensitive user information, it
    can be further used to defeat existing kernel protection mechanisms. (CVE-2021-3923)

    A flaw memory leak in the Linux kernel's eBPF for the Simulated networking device driver in the way user
    uses BPF for the device such that function nsim_map_alloc_elem being called. A local user could use this
    flaw to get unauthorized access to some data. (CVE-2021-4135)

    A data leak flaw was found in the way XFS_IOC_ALLOCSP IOCTL in the XFS filesystem allowed for size
    increase of files with unaligned size. A local attacker could use this flaw to leak data on the XFS
    filesystem otherwise not accessible to them. (CVE-2021-4155)

    An out-of-bounds write flaw was found in the Linux kernel's Aquantia AQtion Ethernet card Atlantic driver
    in the way the ethernet card provides malicious input to the driver. This flaw allows a local user to
    emulate the networking device and crash the system. The highest threat from this vulnerability is to
    confidentiality, integrity, as well as system availability. (CVE-2021-43975)

    In the Linux kernel, the following vulnerability has been resolved:

    sctp: use call_rcu to free endpoint (CVE-2021-46929)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5e: Wrap the tx reporter dump callback to extract the sq (CVE-2021-46931)

    In the Linux kernel, the following vulnerability has been resolved:

    i2c: validate user data in compat ioctl

    Wrong user data may cause warning in i2c_transfer(), ex: zero msgs.Userspace should not be able to trigger
    warnings, so this patch addsvalidation checks for user data in compact ioctl to prevent reportedwarnings
    (CVE-2021-46934)

    In the Linux kernel, the following vulnerability has been resolved:

    net: fix use-after-free in tw_timer_handler (CVE-2021-46936)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/hwpoison: clear MF_COUNT_INCREASED before retrying get_any_page() (CVE-2021-47090)

    In the Linux kernel, the following vulnerability has been resolved:

    Input: elantech - fix stack out of bound access in elantech_change_report_id() (CVE-2021-47097)

    In the Linux kernel, the following vulnerability has been resolved:

    aio: fix use-after-free due to missing POLLFREE handling (CVE-2021-47505)

    In the Linux kernel, the following vulnerability has been resolved:

    nfsd: fix use-after-free due to delegation race (CVE-2021-47506)

    In the Linux kernel, the following vulnerability has been resolved:

    nfsd: Fix nsfd startup race (again) (CVE-2021-47507)

    In the Linux kernel, the following vulnerability has been resolved:

    ethtool: do not perform operations on net devices being unregistered (CVE-2021-47517)

    In the Linux kernel, the following vulnerability has been resolved:

    rxrpc: Fix rxrpc_local leak in rxrpc_lookup_peer() (CVE-2021-47538)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx4_en: Fix an use-after-free bug in mlx4_en_try_alloc_resources() (CVE-2021-47541)

    In the Linux kernel, the following vulnerability has been resolved:

    net: qlogic: qlcnic: Fix a NULL pointer dereference in qlcnic_83xx_add_rings() (CVE-2021-47542)

    In the Linux kernel, the following vulnerability has been resolved:

    ethernet: hisilicon: hns: hns_dsaf_misc: fix a possible array overflow in hns_dsaf_ge_srst_by_port()
    (CVE-2021-47548)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/amd/amdgpu: fix potential memleak (CVE-2021-47550)

    In the Linux kernel, the following vulnerability has been resolved:

    sched/scs: Reset task stack state in bringup_cpu() (CVE-2021-47553)

    In the Linux kernel, the following vulnerability has been resolved:

    mlxsw: spectrum: Protect driver from buggy firmware (CVE-2021-47560)

    In the Linux kernel, the following vulnerability has been resolved:

    proc/vmcore: fix clearing user buffer by properly using clear_user() (CVE-2021-47566)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: scsi_debug: Sanity check block descriptor length in resp_mode_select() (CVE-2021-47576)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: scsi_debug: Don't call kcalloc() if size arg is zero (CVE-2021-47578)

    In the Linux kernel, the following vulnerability has been resolved:

    ovl: fix warning in ovl_create_real() (CVE-2021-47579)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: scsi_debug: Fix type in min_t to avoid stack OOB (CVE-2021-47580)

    In the Linux kernel, the following vulnerability has been resolved:

    iocost: Fix divide-by-zero on donation from low hweight cgroup (CVE-2021-47584)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: fix memory leak in __add_inode_ref() (CVE-2021-47585)

    In the Linux kernel, the following vulnerability has been resolved:

    sit: do not call ipip6_dev_free() from sit_init_net() (CVE-2021-47588)

    In the Linux kernel, the following vulnerability has been resolved:

    igbvf: fix double free in `igbvf_probe` (CVE-2021-47589)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: clear 'kern' flag from fallback sockets (CVE-2021-47593)

    In the Linux kernel, the following vulnerability has been resolved:

    inet_diag: fix kernel-infoleak for UDP sockets (CVE-2021-47597)

    In the Linux kernel, the following vulnerability has been resolved:

    sch_cake: do not call cake_destroy() from cake_init() (CVE-2021-47598)

    In the Linux kernel, the following vulnerability has been resolved:

    dm btree remove: fix use after free in rebalance_children() (CVE-2021-47600)

    In the Linux kernel, the following vulnerability has been resolved:

    audit: improve robustness of the audit queue handling (CVE-2021-47603)

    In the Linux kernel, the following vulnerability has been resolved:

    net: netlink: af_netlink: Prevent empty skb by adding a check on len. (CVE-2021-47606)

    In the Linux kernel, the following vulnerability has been resolved:

    firmware: arm_scpi: Fix string overflow in SCPI genpd driver (CVE-2021-47609)

    A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem
    Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in
    case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local
    user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to
    legacy handling) could use this flaw to escalate their privileges on the system. (CVE-2022-0185)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2022-009.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4135.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4155.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28711.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28712.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28713.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28714.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28715.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3923.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-43975.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46929.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46931.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46934.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46936.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47090.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47097.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47505.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47506.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47507.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47517.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47538.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47541.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47542.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47548.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47550.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47553.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47560.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47566.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47576.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47578.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47579.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47580.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47584.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47585.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47588.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47589.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47593.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47597.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47598.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47600.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47603.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47606.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47609.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0185.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0185");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/26");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-5.10.93-87.444");
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

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list("CVE-2021-3923", "CVE-2021-4135", "CVE-2021-4155", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-43975", "CVE-2021-46929", "CVE-2021-46931", "CVE-2021-46934", "CVE-2021-46936", "CVE-2021-47090", "CVE-2021-47097", "CVE-2021-47505", "CVE-2021-47506", "CVE-2021-47507", "CVE-2021-47517", "CVE-2021-47538", "CVE-2021-47541", "CVE-2021-47542", "CVE-2021-47548", "CVE-2021-47550", "CVE-2021-47553", "CVE-2021-47560", "CVE-2021-47566", "CVE-2021-47576", "CVE-2021-47578", "CVE-2021-47579", "CVE-2021-47580", "CVE-2021-47584", "CVE-2021-47585", "CVE-2021-47588", "CVE-2021-47589", "CVE-2021-47593", "CVE-2021-47597", "CVE-2021-47598", "CVE-2021-47600", "CVE-2021-47603", "CVE-2021-47606", "CVE-2021-47609", "CVE-2022-0185");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.10-2022-009");
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
    {'reference':'bpftool-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-aarch64-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-x86_64-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.93-87.444.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-livepatch-5.10.93-87.444-1.0-0.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-livepatch-5.10.93-87.444-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.93-87.444.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.93-87.444.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'}
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
