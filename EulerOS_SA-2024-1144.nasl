#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190301);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/08");

  script_cve_id(
    "CVE-2013-6885",
    "CVE-2021-39633",
    "CVE-2022-40982",
    "CVE-2022-45887",
    "CVE-2023-1206",
    "CVE-2023-3772",
    "CVE-2023-4206",
    "CVE-2023-4207",
    "CVE-2023-4208",
    "CVE-2023-4387",
    "CVE-2023-4459",
    "CVE-2023-4622",
    "CVE-2023-4623",
    "CVE-2023-4921",
    "CVE-2023-25775",
    "CVE-2023-31085",
    "CVE-2023-39192",
    "CVE-2023-39193",
    "CVE-2023-39197",
    "CVE-2023-39198",
    "CVE-2023-42754",
    "CVE-2023-45862",
    "CVE-2023-45863",
    "CVE-2023-45871"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2024-1144)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - The microcode on AMD 16h 00h through 0Fh processors does not properly handle the interaction between
    locked instructions and write-combined memory types, which allows local users to cause a denial of service
    (system hang) via a crafted application, aka the errata 793 issue. (CVE-2013-6885)

  - In gre_handle_offloads of ip_gre.c, there is a possible page fault due to an invalid memory access. This
    could lead to local information disclosure with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-150694665References: Upstream kernel (CVE-2021-39633)

  - Information exposure through microarchitectural state after transient execution in certain vector
    execution units for some Intel(R) Processors may allow an authenticated user to potentially enable
    information disclosure via local access. (CVE-2022-40982)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/usb/ttusb-dec/ttusb_dec.c has a
    memory leak because of the lack of a dvb_frontend_detach call. (CVE-2022-45887)

  - A hash collision flaw was found in the IPv6 connection lookup table in the Linux kernel's IPv6
    functionality when a user makes a new kind of SYN flood attack. A user located in the local network or
    with a high bandwidth connection can increase the CPU usage of the server that accepts IPV6 connections up
    to 95%. (CVE-2023-1206)

  - Improper access control in the Intel(R) Ethernet Controller RDMA driver for linux before version 1.9.30
    may allow an unauthenticated user to potentially enable escalation of privilege via network access.
    (CVE-2023-25775)

  - An issue was discovered in drivers/mtd/ubi/cdev.c in the Linux kernel 6.2. There is a divide-by-zero error
    in do_div(sz,mtd->erasesize), used indirectly by ctrl_cdev_ioctl, when mtd->erasesize is 0.
    (CVE-2023-31085)

  - A flaw was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem). This issue
    may allow a malicious user with CAP_NET_ADMIN privileges to directly dereference a NULL pointer in
    xfrm_update_ae_params(), leading to a possible kernel crash and denial of service. (CVE-2023-3772)

  - A flaw was found in the Netfilter subsystem in the Linux kernel. The xt_u32 module did not validate the
    fields in the xt_u32 structure. This flaw allows a local privileged attacker to trigger an out-of-bounds
    read by setting the size fields with a value beyond the array boundaries, leading to a crash or
    information disclosure. (CVE-2023-39192)

  - A flaw was found in the Netfilter subsystem in the Linux kernel. The sctp_mt_check did not validate the
    flag_count field. This flaw allows a local privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds
    read, leading to a crash or information disclosure. (CVE-2023-39193)

  - An out-of-bounds read vulnerability was found in Netfilter Connection Tracking (conntrack) in the Linux
    kernel. This flaw allows a remote user to disclose sensitive information via the DCCP protocol.
    (CVE-2023-39197)

  - A race condition was found in the QXL driver in the Linux kernel. The qxl_mode_dumb_create() function
    dereferences the qobj returned by the qxl_gem_object_create_with_handle(), but the handle is the only one
    holding a reference to it. This flaw allows an attacker to guess the returned handle value and trigger a
    use-after-free issue, potentially leading to a denial of service or privilege escalation. (CVE-2023-39198)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_route component can be exploited to
    achieve local privilege escalation. When route4_change() is called on an existing filter, the whole
    tcf_result struct is always copied into the new instance of the filter. This causes a problem when
    updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the
    success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading
    to a use-after-free. We recommend upgrading past commit b80b829e9e2c1b3f7aae34855e04d8f6ecaf13c8.
    (CVE-2023-4206)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_fw component can be exploited to
    achieve local privilege escalation. When fw_change() is called on an existing filter, the whole tcf_result
    struct is always copied into the new instance of the filter. This causes a problem when updating a filter
    bound to a class, as tcf_unbind_filter() is always called on the old instance in the success path,
    decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading to a use-after-
    free. We recommend upgrading past commit 76e42ae831991c828cffa8c37736ebfb831ad5ec. (CVE-2023-4207)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_u32 component can be exploited to
    achieve local privilege escalation. When u32_change() is called on an existing filter, the whole
    tcf_result struct is always copied into the new instance of the filter. This causes a problem when
    updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the
    success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading
    to a use-after-free. We recommend upgrading past commit 3044b16e7c6fe5d24b1cdbcf1bd0a9d92d1ebd81.
    (CVE-2023-4208)

  - A NULL pointer dereference flaw was found in the Linux kernel ipv4 stack. The socket buffer (skb) was
    assumed to be associated with a device before calling __ip_options_compile, which is not always the case
    if the skb is re-routed by ipvs. This issue may allow a local user with CAP_NET_ADMIN privileges to crash
    the system. (CVE-2023-42754)

  - A use-after-free flaw was found in vmxnet3_rq_alloc_rx_buf in drivers/net/vmxnet3/vmxnet3_drv.c in
    VMware's vmxnet3 ethernet NIC driver in the Linux Kernel. This issue could allow a local attacker to crash
    the system due to a double-free while cleaning up vmxnet3_rq_cleanup_all, which could also lead to a
    kernel information leak problem. (CVE-2023-4387)

  - A NULL pointer dereference flaw was found in vmxnet3_rq_cleanup in drivers/net/vmxnet3/vmxnet3_drv.c in
    the networking sub-component in vmxnet3 in the Linux Kernel. This issue may allow a local attacker with
    normal user privilege to cause a denial of service due to a missing sanity check during cleanup.
    (CVE-2023-4459)

  - An issue was discovered in drivers/usb/storage/ene_ub6250.c for the ENE UB6250 reader driver in the Linux
    kernel before 6.2.5. An object could potentially extend beyond the end of an allocation. (CVE-2023-45862)

  - An issue was discovered in lib/kobject.c in the Linux kernel before 6.2.3. With root access, an attacker
    can trigger a race condition that results in a fill_kobj_path out-of-bounds write. (CVE-2023-45863)

  - An issue was discovered in drivers/net/ethernet/intel/igb/igb_main.c in the IGB driver in the Linux kernel
    before 6.5.3. A buffer size may not be adequate for frames larger than the MTU. (CVE-2023-45871)

  - A use-after-free vulnerability in the Linux kernel's af_unix component can be exploited to achieve local
    privilege escalation. The unix_stream_sendpage() function tries to add data to the last skb in the peer's
    recv queue without locking the queue. Thus there is a race where unix_stream_sendpage() could access an
    skb locklessly that is being released by garbage collection, resulting in use-after-free. We recommend
    upgrading past commit 790c2f9d15b594350ae9bca7b236f2b1859de02c. (CVE-2023-4622)

  - A use-after-free vulnerability in the Linux kernel's net/sched: sch_hfsc (HFSC qdisc traffic control)
    component can be exploited to achieve local privilege escalation. If a class with a link-sharing curve
    (i.e. with the HFSC_FSC flag set) has a parent without a link-sharing curve, then init_vf() will call
    vttree_insert() on the parent, but vttree_remove() will be skipped in update_vf(). This leaves a dangling
    pointer that can cause a use-after-free. We recommend upgrading past commit
    b3d26c5702c7d6c45456326e56d2ccf3f103e60f. (CVE-2023-4623)

  - A use-after-free vulnerability in the Linux kernel's net/sched: sch_qfq component can be exploited to
    achieve local privilege escalation. When the plug qdisc is used as a class of the qfq qdisc, sending
    network packets triggers use-after-free in qfq_dequeue() due to the incorrect .peek handler of sch_plug
    and lack of error checking in agg_dequeue(). We recommend upgrading past commit
    8fc134fee27f2263988ae38920bc03da416b03d8. (CVE-2023-4921)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1144
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?daf708e7");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39633");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-25775");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/08");

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
  "kernel-3.10.0-862.14.1.5.h816.eulerosv2r7",
  "kernel-devel-3.10.0-862.14.1.5.h816.eulerosv2r7",
  "kernel-headers-3.10.0-862.14.1.5.h816.eulerosv2r7",
  "kernel-tools-3.10.0-862.14.1.5.h816.eulerosv2r7",
  "kernel-tools-libs-3.10.0-862.14.1.5.h816.eulerosv2r7",
  "perf-3.10.0-862.14.1.5.h816.eulerosv2r7",
  "python-perf-3.10.0-862.14.1.5.h816.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
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
