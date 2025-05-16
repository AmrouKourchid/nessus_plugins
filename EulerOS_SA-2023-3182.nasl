#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188939);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2023-1206",
    "CVE-2023-3772",
    "CVE-2023-4128",
    "CVE-2023-4194",
    "CVE-2023-4206",
    "CVE-2023-4207",
    "CVE-2023-4208",
    "CVE-2023-4622",
    "CVE-2023-4623",
    "CVE-2023-4921",
    "CVE-2023-21400",
    "CVE-2023-42753"
  );

  script_name(english:"EulerOS 2.0 SP10 : kernel (EulerOS-SA-2023-3182)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - A hash collision flaw was found in the IPv6 connection lookup table in the Linux kernel's IPv6
    functionality when a user makes a new kind of SYN flood attack. A user located in the local network or
    with a high bandwidth connection can increase the CPU usage of the server that accepts IPV6 connections up
    to 95%. (CVE-2023-1206)

  - In multiple functions of io_uring.c, there is a possible kernel memory corruption due to improper locking.
    This could lead to local escalation of privilege in the kernel with System execution privileges needed.
    User interaction is not needed for exploitation. (CVE-2023-21400)

  - A flaw was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem). This issue
    may allow a malicious user with CAP_NET_ADMIN privileges to directly dereference a NULL pointer in
    xfrm_update_ae_params(), leading to a possible kernel crash and denial of service. (CVE-2023-3772)

  - A flaw was found in the Linux kernel's TUN/TAP functionality. This issue could allow a local user to
    bypass network filters and gain unauthorized access to some resources. The original patches fixing
    CVE-2023-1076 are incorrect or incomplete. The problem is that the following upstream commits -
    a096ccca6e50 ('tun: tun_chr_open(): correctly initialize socket uid'), - 66b2c338adce ('tap: tap_open():
    correctly initialize socket uid'), pass 'inode->i_uid' to sock_init_data_uid() as the last parameter and
    that turns out to not be accurate. (CVE-2023-4194)

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

  - An array indexing vulnerability was found in the netfilter subsystem of the Linux kernel. A missing macro
    could lead to a miscalculation of the `h->nets` array offset, providing attackers with the primitive to
    arbitrarily increment/decrement a memory buffer out-of-bound. This issue may allow a local user to crash
    the system or potentially escalate their privileges on the system. (CVE-2023-42753)

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
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3182
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?730b433e");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4921");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.19.90-vhulk2211.3.0.h1620.eulerosv2r10",
  "kernel-abi-stablelists-4.19.90-vhulk2211.3.0.h1620.eulerosv2r10",
  "kernel-tools-4.19.90-vhulk2211.3.0.h1620.eulerosv2r10",
  "kernel-tools-libs-4.19.90-vhulk2211.3.0.h1620.eulerosv2r10",
  "python3-perf-4.19.90-vhulk2211.3.0.h1620.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

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
