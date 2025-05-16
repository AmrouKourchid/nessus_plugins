#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188798);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id(
    "CVE-2020-36516",
    "CVE-2022-36280",
    "CVE-2022-41858",
    "CVE-2022-45886",
    "CVE-2023-0458",
    "CVE-2023-1206",
    "CVE-2023-1513",
    "CVE-2023-2124",
    "CVE-2023-2176",
    "CVE-2023-2269",
    "CVE-2023-2513",
    "CVE-2023-3106",
    "CVE-2023-3108",
    "CVE-2023-3141",
    "CVE-2023-3159",
    "CVE-2023-3161",
    "CVE-2023-3268",
    "CVE-2023-3358",
    "CVE-2023-3609",
    "CVE-2023-3611",
    "CVE-2023-3772",
    "CVE-2023-3776",
    "CVE-2023-30456",
    "CVE-2023-31436",
    "CVE-2023-32269",
    "CVE-2023-34256",
    "CVE-2023-35001",
    "CVE-2023-35824"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.6 : kernel (EulerOS-SA-2023-3418)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel package installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - An issue was discovered in the Linux kernel through 5.16.11. The mixed IPID assignment method with the
    hash-based IPID assignment policy allows an off-path attacker to inject data into a victim's TCP session
    or terminate that session. (CVE-2020-36516)

  - An out-of-bounds(OOB) memory access vulnerability was found in vmwgfx driver in
    drivers/gpu/vmxgfx/vmxgfx_kms.c in GPU component in the Linux kernel with device file '/dev/dri/renderD128
    (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing
    a denial of service(DoS). (CVE-2022-36280)

  - A flaw was found in the Linux kernel. A NULL pointer dereference may occur while a slip driver is in
    progress to detach in sl_tx_timeout in drivers/net/slip/slip.c. This issue could allow an attacker to
    crash the system or leak internal kernel information. (CVE-2022-41858)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvb_net.c has a
    .disconnect versus dvb_device_open race condition that leads to a use-after-free. (CVE-2022-45886)

  - A speculative pointer dereference problem exists in the Linux Kernel on the do_prlimit() function. The
    resource argument value is controlled and is used in pointer arithmetic for the 'rlim' variable and can be
    used to leak the contents. We recommend upgrading past version 6.1.8 or commit
    739790605705ddcf18f21782b9c99ad7d53a8c11 (CVE-2023-0458)

  - A hash collision flaw was found in the IPv6 connection lookup table in the Linux kernel's IPv6
    functionality when a user makes a new kind of SYN flood attack. A user located in the local network or
    with a high bandwidth connection can increase the CPU usage of the server that accepts IPV6 connections up
    to 95%. (CVE-2023-1206)

  - A flaw was found in KVM. When calling the KVM_GET_DEBUGREGS ioctl, on 32-bit systems, there might be some
    uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an
    information leak. (CVE-2023-1513)

  - An out-of-bounds memory access flaw was found in the Linux kernel's XFS file system in how a user restores
    an XFS image after failure (with a dirty log journal). This flaw allows a local user to crash or
    potentially escalate their privileges on the system. (CVE-2023-2124)

  - A vulnerability was found in compare_netdev_and_ip in drivers/infiniband/core/cma.c in RDMA in the Linux
    Kernel. The improper cleanup results in out-of-boundary read, where a local user can utilize this problem
    to crash the system or escalation of privilege. (CVE-2023-2176)

  - A denial of service problem was found, due to a possible recursive locking scenario, resulting in a
    deadlock in table_clear in drivers/md/dm-ioctl.c in the Linux Kernel Device Mapper-Multipathing sub-
    component. (CVE-2023-2269)

  - A use-after-free vulnerability was found in the Linux kernel's ext4 filesystem in the way it handled the
    extra inode size for extended attributes. This flaw could allow a privileged local user to cause a system
    crash or other undefined behaviors. (CVE-2023-2513)

  - An issue was discovered in arch/x86/kvm/vmx/nested.c in the Linux kernel before 6.2.8. nVMX on x86_64
    lacks consistency checks for CR0 and CR4. (CVE-2023-30456)

  - A NULL pointer dereference vulnerability was found in netlink_dump. This issue can occur when the Netlink
    socket receives the message(sendmsg) for the XFRM_MSG_GETSA, XFRM_MSG_GETPOLICY type message, and the DUMP
    flag is set and can cause a denial of service or possibly another unspecified impact. Due to the nature of
    the flaw, privilege escalation cannot be fully ruled out, although it is unlikely. (CVE-2023-3106)

  - A flaw was found in the subsequent get_user_pages_fast in the Linux kernel's interface for symmetric key
    cipher algorithms in the skcipher_recvmsg of crypto/algif_skcipher.c function. This flaw allows a local
    user to crash the system. (CVE-2023-3108)

  - A use-after-free flaw was found in r592_remove in drivers/memstick/host/r592.c in media access in the
    Linux Kernel. This flaw allows a local attacker to crash the system at device disconnect, possibly leading
    to a kernel information leak. (CVE-2023-3141)

  - qfq_change_class in net/sched/sch_qfq.c in the Linux kernel before 6.2.13 allows an out-of-bounds write
    because lmax can exceed QFQ_MIN_LMAX. (CVE-2023-31436)

  - A use after free issue was discovered in driver/firewire in outbound_phy_packet_callback in the Linux
    Kernel. In this flaw a local attacker with special privilege may cause a use after free problem when
    queue_event() fails. (CVE-2023-3159)

  - A flaw was found in the Framebuffer Console (fbcon) in the Linux Kernel. When providing font->width and
    font->height greater than 32 to fbcon_set_font, since there are no checks in place, a shift-out-of-bounds
    occurs leading to undefined behavior and possible denial of service. (CVE-2023-3161)

  - An issue was discovered in the Linux kernel before 6.1.11. In net/netrom/af_netrom.c, there is a use-
    after-free because accept is also allowed for a successfully connected AF_NETROM socket. However, in order
    for an attacker to exploit this, the system must have netrom routing configured or the attacker must have
    the CAP_NET_ADMIN capability. (CVE-2023-32269)

  - An out of bounds (OOB) memory access flaw was found in the Linux kernel in relay_file_read_start_pos in
    kernel/relay.c in the relayfs. This flaw could allow a local attacker to crash the system or leak kernel
    internal information. (CVE-2023-3268)

  - A null pointer dereference was found in the Linux kernel's Integrated Sensor Hub (ISH) driver. This issue
    could allow a local user to crash the system. (CVE-2023-3358)

  - An issue was discovered in the Linux kernel before 6.3.3. There is an out-of-bounds read in crc16 in
    lib/crc16.c when called from fs/ext4/super.c because ext4_group_desc_csum does not properly check an
    offset. NOTE: this is disputed by third parties because the kernel is not intended to defend against
    attackers with the stated 'When modifying the block device while it is mounted by the filesystem' access.
    (CVE-2023-34256)

  - Linux Kernel nftables Out-Of-Bounds Read/Write Vulnerability; nft_byteorder poorly handled vm register
    contents when CAP_NET_ADMIN is in any user or network namespace (CVE-2023-35001)

  - An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in dm1105_remove in
    drivers/media/pci/dm1105/dm1105.c. (CVE-2023-35824)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_u32 component can be exploited to
    achieve local privilege escalation. If tcf_change_indev() fails, u32_set_parms() will immediately return
    an error after incrementing or decrementing the reference counter in tcf_bind_filter(). If an attacker can
    control the reference counter and set it to zero, they can cause the reference to be freed, leading to a
    use-after-free vulnerability. We recommend upgrading past commit 04c55383fa5689357bcdd2c8036725a55ed632bc.
    (CVE-2023-3609)

  - An out-of-bounds write vulnerability in the Linux kernel's net/sched: sch_qfq component can be exploited
    to achieve local privilege escalation. The qfq_change_agg() function in net/sched/sch_qfq.c allows an out-
    of-bounds write because lmax is updated according to packet sizes without bounds checks. We recommend
    upgrading past commit 3e337087c3b5805fe0b8a46ba622a962880b5d64. (CVE-2023-3611)

  - A flaw was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem). This issue
    may allow a malicious user with CAP_NET_ADMIN privileges to directly dereference a NULL pointer in
    xfrm_update_ae_params(), leading to a possible kernel crash and denial of service. (CVE-2023-3772)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_fw component can be exploited to
    achieve local privilege escalation. If tcf_change_indev() fails, fw_set_parms() will immediately return an
    error after incrementing or decrementing the reference counter in tcf_bind_filter(). If an attacker can
    control the reference counter and set it to zero, they can cause the reference to be freed, leading to a
    use-after-free vulnerability. We recommend upgrading past commit 0323bce598eea038714f941ce2b22541c46d488f.
    (CVE-2023-3776)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3418
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?129f333b");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36516");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-3776");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-3.10.0-862.14.1.6_223"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
