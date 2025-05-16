#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205028);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/06");

  script_cve_id(
    "CVE-2021-33631",
    "CVE-2021-46936",
    "CVE-2021-46952",
    "CVE-2023-51043",
    "CVE-2023-52435",
    "CVE-2023-52439",
    "CVE-2023-52445",
    "CVE-2024-0607"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2024-2070)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    In the Linux kernel, the following vulnerability has been resolved: net: fix use-after-free in
    tw_timer_handler A real world panic issue was found as follow in Linux 5.4. BUG: unable to handle page
    fault for address: ffffde49a863de28 PGD 7e6fe62067 P4D 7e6fe62067 PUD 7e6fe63067 PMD f51e064067 PTE 0 RIP:
    0010:tw_timer_handler+0x20/0x40 Call Trace: IRQ call_timer_fn+0x2b/0x120
    run_timer_softirq+0x1ef/0x450 __do_softirq+0x10d/0x2b8 irq_exit+0xc7/0xd0
    smp_apic_timer_interrupt+0x68/0x120 apic_timer_interrupt+0xf/0x20 This issue was also reported since 2017
    in the thread [1], unfortunately, the issue was still can be reproduced after fixing DCCP. The
    ipv4_mib_exit_net is called before tcp_sk_exit_batch when a net namespace is destroyed since tcp_sk_ops is
    registered befrore ipv4_mib_ops, which means tcp_sk_ops is in the front of ipv4_mib_ops in the list of
    pernet_list. There will be a use-after-free on net-mib.net_statistics in tw_timer_handler after
    ipv4_mib_exit_net if there are some inflight time-wait timers. This bug is not introduced by commit
    f2bf415cfed7 ('mib: add net to NET_ADD_STATS_BH') since the net_statistics is a global variable instead of
    dynamic allocation and freeing. Actually, commit 61a7e26028b9 ('mib: put net statistics on struct net')
    introduces the bug since it put net statistics on struct net and free it when net namespace is destroyed.
    Moving init_ipv4_mibs() to the front of tcp_init() to fix this bug and replace pr_crit() with panic()
    since continuing is meaningless when init_ipv4_mibs() fails. [1]
    https://groups.google.com/g/syzkaller/c/p1tn-_Kc6l4/m/smuL_FMAAgAJ?pli=1(CVE-2021-46936)

    In the Linux kernel, the following vulnerability has been resolved: NFS: fs_context: validate UDP retrans
    to prevent shift out-of-bounds Fix shift out-of-bounds in xprt_calc_majortimeo(). This is caused by a
    garbage timeout (retrans) mount option being passed to nfs mount, in this case from syzkaller. If the
    protocol is XPRT_TRANSPORT_UDP, then 'retrans' is a shift value for a 64-bit long integer, so 'retrans'
    cannot be = 64. If it is = 64, fail the mount and return an error.(CVE-2021-46952)

    In the Linux kernel, the following vulnerability has been resolved: media: pvrusb2: fix use after free on
    context disconnection Upon module load, a kthread is created targeting the pvr2_context_thread_func
    function, which may call pvr2_context_destroy and thus call kfree() on the context object. However, that
    might happen before the usb hub_event handler is able to notify the driver. This patch adds a sanity check
    before the invalid read reported by syzbot, within the context disconnection call stack.(CVE-2023-52445)

    In the Linux kernel, the following vulnerability has been resolved: net: prevent mss overflow in
    skb_segment() Once again syzbot is able to crash the kernel in skb_segment() [1] GSO_BY_FRAGS is a
    forbidden value, but unfortunately the following computation in skb_segment() can reach it quite easily :
    mss = mss * partial_segs; 65535 = 3 * 5 * 17 * 257, so many initial values of mss can lead to a bad final
    result. Make sure to limit segmentation so that the new mss value is smaller than
    GSO_BY_FRAGS.(CVE-2023-52435)

    In the Linux kernel, the following vulnerability has been resolved: uio: Fix use-after-free in uio_open
    core-1 core-2 ------------------------------------------------------- uio_unregister_device uio_open idev
    = idr_find() device_unregister(idev-dev) put_device(idev-dev) uio_device_release
    get_device(idev-dev) kfree(idev) uio_free_minor(minor) uio_release put_device(idev-dev)
    kfree(idev) ------------------------------------------------------- In the core-1 uio_unregister_device(),
    the device_unregister will kfree idev when the idev-dev kobject ref is 1. But after core-1
    device_unregister, put_device and before doing kfree, the core-2 may get_device. Then: 1. After core-1
    kfree idev, the core-2 will do use-after-free for idev. 2. When core-2 do uio_release and put_device, the
    idev will be double freed. To address this issue, we can get idev atomic  inc idev reference with
    minor_lock.(CVE-2023-52439)

    In the Linux kernel before 6.4.5, drivers/gpu/drm/drm_atomic.c has a use-after-free during a race
    condition between a nonblocking atomic commit and a driver unload.(CVE-2023-51043)

    A flaw was found in the Netfilter subsystem in the Linux kernel. The issue is in the nft_byteorder_eval()
    function, where the code iterates through a loop and writes to the `dst` array. On each iteration, 8 bytes
    are written, but `dst` is an array of u32, so each element only has space for 4 bytes. That means every
    iteration overwrites part of the previous element corrupting this array of u32. This flaw allows a local
    user to cause a denial of service or potentially break NetFilter functionality.(CVE-2024-0607)

    Integer Overflow or Wraparound vulnerability in openEuler kernel on Linux (filesystem modules) allows
    Forced Integer Overflow.This issue affects openEuler kernel: from 4.19.90 before 4.19.90-2401.3, from
    5.10.0-60.18.0 before 5.10.0-183.0.0.(CVE-2021-33631)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2070
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a6dd6eb");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52445");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-3.10.0-862.14.1.5.h839.eulerosv2r7",
  "kernel-devel-3.10.0-862.14.1.5.h839.eulerosv2r7",
  "kernel-headers-3.10.0-862.14.1.5.h839.eulerosv2r7",
  "kernel-tools-3.10.0-862.14.1.5.h839.eulerosv2r7",
  "kernel-tools-libs-3.10.0-862.14.1.5.h839.eulerosv2r7",
  "perf-3.10.0-862.14.1.5.h839.eulerosv2r7",
  "python-perf-3.10.0-862.14.1.5.h839.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
