##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4060 and
# CentOS Errata and Security Advisory 2020:4060 respectively.
##

include('compat.inc');

if (description)
{
  script_id(141619);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2017-18551",
    "CVE-2018-20836",
    "CVE-2019-9454",
    "CVE-2019-9458",
    "CVE-2019-12614",
    "CVE-2019-15217",
    "CVE-2019-15807",
    "CVE-2019-15917",
    "CVE-2019-16231",
    "CVE-2019-16233",
    "CVE-2019-16994",
    "CVE-2019-17053",
    "CVE-2019-17055",
    "CVE-2019-18808",
    "CVE-2019-19046",
    "CVE-2019-19055",
    "CVE-2019-19058",
    "CVE-2019-19059",
    "CVE-2019-19062",
    "CVE-2019-19063",
    "CVE-2019-19332",
    "CVE-2019-19447",
    "CVE-2019-19523",
    "CVE-2019-19524",
    "CVE-2019-19530",
    "CVE-2019-19534",
    "CVE-2019-19537",
    "CVE-2019-19767",
    "CVE-2019-19807",
    "CVE-2019-20054",
    "CVE-2019-20095",
    "CVE-2019-20636",
    "CVE-2020-1749",
    "CVE-2020-2732",
    "CVE-2020-8647",
    "CVE-2020-8649",
    "CVE-2020-9383",
    "CVE-2020-10690",
    "CVE-2020-10732",
    "CVE-2020-10742",
    "CVE-2020-10751",
    "CVE-2020-10942",
    "CVE-2020-11565",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-14305"
  );
  script_bugtraq_id(108196, 108550);
  script_xref(name:"RHSA", value:"2020:4060");

  script_name(english:"CentOS 7 : kernel (RHSA-2020:4060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2020:4060 advisory.

  - An issue was discovered in drivers/i2c/i2c-core-smbus.c in the Linux kernel before 4.14.15. There is an
    out of bounds write in the function i2c_smbus_xfer_emulated. (CVE-2017-18551)

  - An issue was discovered in the Linux kernel before 4.20. There is a race condition in smp_task_timedout()
    and smp_task_done() in drivers/scsi/libsas/sas_expander.c, leading to a use-after-free. (CVE-2018-20836)

  - An issue was discovered in dlpar_parse_cc_property in arch/powerpc/platforms/pseries/dlpar.c in the Linux
    kernel through 5.1.6. There is an unchecked kstrdup of prop->name, which might allow an attacker to cause
    a denial of service (NULL pointer dereference and system crash). (CVE-2019-12614)

  - An issue was discovered in the Linux kernel before 5.2.3. There is a NULL pointer dereference caused by a
    malicious USB device in the drivers/media/usb/zr364xx/zr364xx.c driver. (CVE-2019-15217)

  - In the Linux kernel before 5.1.13, there is a memory leak in drivers/scsi/libsas/sas_expander.c when SAS
    expander discovery fails. This will cause a BUG and denial of service. (CVE-2019-15807)

  - An issue was discovered in the Linux kernel before 5.0.5. There is a use-after-free issue when
    hci_uart_register_dev() fails in hci_uart_set_proto() in drivers/bluetooth/hci_ldisc.c. (CVE-2019-15917)

  - drivers/net/fjes/fjes_main.c in the Linux kernel 5.2.14 does not check the alloc_workqueue return value,
    leading to a NULL pointer dereference. (CVE-2019-16231)

  - drivers/scsi/qla2xxx/qla_os.c in the Linux kernel 5.2.14 does not check the alloc_workqueue return value,
    leading to a NULL pointer dereference. (CVE-2019-16233)

  - In the Linux kernel before 5.0, a memory leak exists in sit_init_net() in net/ipv6/sit.c when
    register_netdev() fails to register sitn->fb_tunnel_dev, which may cause denial of service, aka
    CID-07f12b26e21a. (CVE-2019-16994)

  - ieee802154_create in net/ieee802154/socket.c in the AF_IEEE802154 network module in the Linux kernel
    through 5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket,
    aka CID-e69dbd4619e7. (CVE-2019-17053)

  - base_sock_create in drivers/isdn/mISDN/socket.c in the AF_ISDN network module in the Linux kernel through
    5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket, aka
    CID-b91ee4aa2a21. (CVE-2019-17055)

  - A memory leak in the ccp_run_sha_cmd() function in drivers/crypto/ccp/ccp-ops.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of service (memory consumption), aka CID-128c66429247.
    (CVE-2019-18808)

  - A memory leak in the __ipmi_bmc_register() function in drivers/char/ipmi/ipmi_msghandler.c in the Linux
    kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    ida_simple_get() failure, aka CID-4aa7afb0ee20. NOTE: third parties dispute the relevance of this because
    an attacker cannot realistically control this failure at probe time (CVE-2019-19046)

  - A memory leak in the nl80211_get_ftm_responder_stats() function in net/wireless/nl80211.c in the Linux
    kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    nl80211hdr_put() failures, aka CID-1399c59fa929. NOTE: third parties dispute the relevance of this because
    it occurs on a code path where a successful allocation has already occurred (CVE-2019-19055)

  - A memory leak in the alloc_sgtable() function in drivers/net/wireless/intel/iwlwifi/fw/dbg.c in the Linux
    kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    alloc_page() failures, aka CID-b4b814fec1a5. (CVE-2019-19058)

  - Multiple memory leaks in the iwl_pcie_ctxt_info_gen3_init() function in
    drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info-gen3.c in the Linux kernel through 5.3.11 allow
    attackers to cause a denial of service (memory consumption) by triggering iwl_pcie_init_fw_sec() or
    dma_alloc_coherent() failures, aka CID-0f4f199443fa. (CVE-2019-19059)

  - A memory leak in the crypto_report() function in crypto/crypto_user_base.c in the Linux kernel through
    5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    crypto_report_alg() failures, aka CID-ffdde5932042. (CVE-2019-19062)

  - Two memory leaks in the rtl_usb_probe() function in drivers/net/wireless/realtek/rtlwifi/usb.c in the
    Linux kernel through 5.3.11 allow attackers to cause a denial of service (memory consumption), aka
    CID-3f9361695113. (CVE-2019-19063)

  - An out-of-bounds memory write issue was found in the Linux Kernel, version 3.13 through 5.4, in the way
    the Linux kernel's KVM hypervisor handled the 'KVM_GET_EMULATED_CPUID' ioctl(2) request to get CPUID
    features emulated by the KVM hypervisor. A user or process able to access the '/dev/kvm' device could use
    this flaw to crash the system, resulting in a denial of service. (CVE-2019-19332)

  - In the Linux kernel 5.0.21, mounting a crafted ext4 filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in ext4_put_super in fs/ext4/super.c, related to dump_orphan_list
    in fs/ext4/super.c. (CVE-2019-19447)

  - In the Linux kernel before 5.3.7, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/usb/misc/adutux.c driver, aka CID-44efc269db79. (CVE-2019-19523)

  - In the Linux kernel before 5.3.12, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/input/ff-memless.c driver, aka CID-fa3a5a1880c9. (CVE-2019-19524)

  - In the Linux kernel before 5.2.10, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/usb/class/cdc-acm.c driver, aka CID-c52873e5a1ef. (CVE-2019-19530)

  - In the Linux kernel before 5.3.11, there is an info-leak bug that can be caused by a malicious USB device
    in the drivers/net/can/usb/peak_usb/pcan_usb_core.c driver, aka CID-f7a1337f0d29. (CVE-2019-19534)

  - In the Linux kernel before 5.2.10, there is a race condition bug that can be caused by a malicious USB
    device in the USB character device driver layer, aka CID-303911cfc5b9. This affects
    drivers/usb/core/file.c. (CVE-2019-19537)

  - The Linux kernel before 5.4.2 mishandles ext4_expand_extra_isize, as demonstrated by use-after-free errors
    in __ext4_expand_extra_isize and ext4_xattr_set_entry, related to fs/ext4/inode.c and fs/ext4/super.c, aka
    CID-4ea99936a163. (CVE-2019-19767)

  - In the Linux kernel before 5.3.11, sound/core/timer.c has a use-after-free caused by erroneous code
    refactoring, aka CID-e7af6307a8a5. This is related to snd_timer_open and snd_timer_close_locked. The
    timeri variable was originally intended to be for a newly created timer instance, but was used for a
    different purpose after refactoring. (CVE-2019-19807)

  - In the Linux kernel before 5.0.6, there is a NULL pointer dereference in drop_sysctl_table() in
    fs/proc/proc_sysctl.c, related to put_links, aka CID-23da9588037e. (CVE-2019-20054)

  - mwifiex_tm_cmd in drivers/net/wireless/marvell/mwifiex/cfg80211.c in the Linux kernel before 5.1.6 has
    some error-handling cases that did not free allocated hostcmd memory, aka CID-003b686ace82. This will
    cause a memory leak and denial of service. (CVE-2019-20095)

  - In the Linux kernel before 5.4.12, drivers/input/input.c has out-of-bounds writes via a crafted keycode
    table, as demonstrated by input_set_keycode, aka CID-cb222aed03d7. (CVE-2019-20636)

  - In the Android kernel in i2c driver there is a possible out of bounds write due to memory corruption. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation. (CVE-2019-9454)

  - In the Android kernel in the video driver there is a use after free due to a race condition. This could
    lead to local escalation of privilege with no additional execution privileges needed. User interaction is
    not needed for exploitation. (CVE-2019-9458)

  - There is a use-after-free in kernel versions before 5.5 due to a race condition between the release of
    ptp_clock and cdev while resource deallocation. When a (high privileged) process allocates a ptp device
    file (like /dev/ptpX) and voluntarily goes to sleep. During this time if the underlying device is removed,
    it can cause an exploitable condition as the process wakes up to terminate and clean all attached files.
    The system crashes due to the cdev structure being invalid (as already freed) which is pointed to by the
    inode. (CVE-2020-10690)

  - A flaw was found in the Linux kernel's implementation of Userspace core dumps. This flaw allows an
    attacker with a local account to crash a trivial program and exfiltrate private kernel data.
    (CVE-2020-10732)

  - A flaw was found in the Linux kernel. An index buffer overflow during Direct IO write leading to the NFS
    client to crash. In some cases, a reach out of the index after one memory allocation by kmalloc will cause
    a kernel panic. The highest threat from this vulnerability is to data confidentiality and system
    availability. (CVE-2020-10742)

  - A flaw was found in the Linux kernels SELinux LSM hook implementation before version 5.7, where it
    incorrectly assumed that an skb would only contain a single netlink message. The hook would incorrectly
    only validate the first netlink message in the skb and allow or deny the rest of the messages within the
    skb with the granted permission without further processing. (CVE-2020-10751)

  - In the Linux kernel before 5.5.8, get_raw_socket in drivers/vhost/net.c lacks validation of an sk_family
    field, which might allow attackers to trigger kernel stack corruption via crafted system calls.
    (CVE-2020-10942)

  - An issue was discovered in the Linux kernel through 5.6.2. mpol_parse_str in mm/mempolicy.c has a stack-
    based out-of-bounds write because an empty nodelist is mishandled during mount option parsing, aka CID-
    aa9f7d5172fa. NOTE: Someone in the security community disagrees that this is a vulnerability because the
    issue is a bug in parsing mount options which can only be specified by a privileged user, so triggering
    the bug does not grant any powers not already held. (CVE-2020-11565)

  - An issue was discovered in the Linux kernel through 5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka CID-83c6f2390040. (CVE-2020-12770)

  - A signal access-control issue was discovered in the Linux kernel before 5.6.5, aka CID-7395ea4e65c2.
    Because exec_id in include/linux/sched.h is only 32 bits, an integer overflow can interfere with a
    do_notify_parent protection mechanism. A child process can send an arbitrary signal to a parent process in
    a different security domain. Exploitation limitations include the amount of elapsed time before an integer
    overflow occurs, and the lack of scenarios where signals to a parent process present a substantial
    operational threat. (CVE-2020-12826)

  - An out-of-bounds memory write flaw was found in how the Linux kernel's Voice Over IP H.323 connection
    tracking functionality handled connections on ipv6 port 1720. This flaw allows an unauthenticated remote
    user to crash the system, causing a denial of service. The highest threat from this vulnerability is to
    confidentiality, integrity, as well as system availability. (CVE-2020-14305)

  - A flaw was found in the Linux kernel's implementation of some networking protocols in IPsec, such as VXLAN
    and GENEVE tunnels over IPv6. When an encrypted tunnel is created between two hosts, the kernel isn't
    correctly routing tunneled data over the encrypted link; rather sending the data unencrypted. This would
    allow anyone in between the two endpoints to read the traffic unencrypted. The main threat from this
    vulnerability is to data confidentiality. (CVE-2020-1749)

  - A flaw was discovered in the way that the KVM hypervisor handled instruction emulation for an L2 guest
    when nested virtualisation is enabled. Under some circumstances, an L2 guest may trick the L0 guest into
    accessing sensitive L1 resources that should be inaccessible to the L2 guest. (CVE-2020-2732)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vc_do_resize function in
    drivers/tty/vt/vt.c. (CVE-2020-8647)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vgacon_invert_region
    function in drivers/video/console/vgacon.c. (CVE-2020-8649)

  - An issue was discovered in the Linux kernel 3.16 through 5.5.6. set_fdc in drivers/block/floppy.c leads to
    a wait_til_ready out-of-bounds read because the FDC index is not checked for errors before assigning it,
    aka CID-2e90ca68b0d2. (CVE-2020-9383)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4060");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20836");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14305");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'bpftool-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-whitelists-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-whitelists-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-bootwrapper-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-bootwrapper-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kdump-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kdump-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kdump-devel-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kdump-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / etc');
}
