#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193014);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/30");

  script_cve_id(
    "CVE-2021-33631",
    "CVE-2022-48619",
    "CVE-2023-6040",
    "CVE-2023-6121",
    "CVE-2023-7192",
    "CVE-2023-51042",
    "CVE-2023-51043",
    "CVE-2023-52340",
    "CVE-2023-52435",
    "CVE-2023-52439",
    "CVE-2024-0340",
    "CVE-2024-0565",
    "CVE-2024-0607",
    "CVE-2024-0639",
    "CVE-2024-1086"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/20");

  script_name(english:"EulerOS 2.0 SP9 : kernel (EulerOS-SA-2024-1488)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - Integer Overflow or Wraparound vulnerability in openEuler kernel on Linux (filesystem modules) allows
    Forced Integer Overflow.This issue affects openEuler kernel: from 4.19.90 before 4.19.90-2401.3, from
    5.10.0-60.18.0 before 5.10.0-183.0.0. (CVE-2021-33631)

  - An issue was discovered in drivers/input/input.c in the Linux kernel before 5.17.10. An attacker can cause
    a denial of service (panic) because input_set_capability mishandles the situation in which an event code
    falls outside of a bitmap. (CVE-2022-48619)

  - In the Linux kernel before 6.4.12, amdgpu_cs_wait_all_fences in drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c has
    a fence use-after-free. (CVE-2023-51042)

  - In the Linux kernel before 6.4.5, drivers/gpu/drm/drm_atomic.c has a use-after-free during a race
    condition between a nonblocking atomic commit and a driver unload. (CVE-2023-51043)

  - In the Linux kernel, the following vulnerability has been resolved: net: prevent mss overflow in
    skb_segment() Once again syzbot is able to crash the kernel in skb_segment() [1] GSO_BY_FRAGS is a
    forbidden value, but unfortunately the following computation in skb_segment() can reach it quite easily :
    mss = mss * partial_segs; 65535 = 3 * 5 * 17 * 257, so many initial values of mss can lead to a bad final
    result. Make sure to limit segmentation so that the new mss value is smaller than GSO_BY_FRAGS. [1]
    general protection fault, probably for non-canonical address 0xdffffc000000000e: 0000 [#1] PREEMPT SMP
    KASAN KASAN: null-ptr-deref in range [0x0000000000000070-0x0000000000000077] CPU: 1 PID: 5079 Comm: syz-
    executor993 Not tainted 6.7.0-rc4-syzkaller-00141-g1ae4cd3cbdd0 #0 Hardware name: Google Google Compute
    Engine/Google Compute Engine, BIOS Google 11/10/2023 RIP: 0010:skb_segment+0x181d/0x3f30
    net/core/skbuff.c:4551 Code: 83 e3 02 e9 fb ed ff ff e8 90 68 1c f9 48 8b 84 24 f8 00 00 00 48 8d 78 70 48
    b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1 ea 03 <0f> b6 04 02 84 c0 74 08 3c 03 0f 8e 8a 21 00 00 48 8b 84
    24 f8 00 RSP: 0018:ffffc900043473d0 EFLAGS: 00010202 RAX: dffffc0000000000 RBX: 0000000000010046 RCX:
    ffffffff886b1597 RDX: 000000000000000e RSI: ffffffff886b2520 RDI: 0000000000000070 RBP: ffffc90004347578
    R08: 0000000000000005 R09: 000000000000ffff R10: 000000000000ffff R11: 0000000000000002 R12:
    ffff888063202ac0 R13: 0000000000010000 R14: 000000000000ffff R15: 0000000000000046 FS:
    0000555556e7e380(0000) GS:ffff8880b9900000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 CR2: 0000000020010000 CR3: 0000000027ee2000 CR4: 00000000003506f0 DR0: 0000000000000000
    DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
    0000000000000400 Call Trace: <TASK> udp6_ufo_fragment+0xa0e/0xd00 net/ipv6/udp_offload.c:109
    ipv6_gso_segment+0x534/0x17e0 net/ipv6/ip6_offload.c:120 skb_mac_gso_segment+0x290/0x610 net/core/gso.c:53
    __skb_gso_segment+0x339/0x710 net/core/gso.c:124 skb_gso_segment include/net/gso.h:83 [inline]
    validate_xmit_skb+0x36c/0xeb0 net/core/dev.c:3626 __dev_queue_xmit+0x6f3/0x3d60 net/core/dev.c:4338
    dev_queue_xmit include/linux/netdevice.h:3134 [inline] packet_xmit+0x257/0x380 net/packet/af_packet.c:276
    packet_snd net/packet/af_packet.c:3087 [inline] packet_sendmsg+0x24c6/0x5220 net/packet/af_packet.c:3119
    sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg+0xd5/0x180 net/socket.c:745
    __sys_sendto+0x255/0x340 net/socket.c:2190 __do_sys_sendto net/socket.c:2202 [inline] __se_sys_sendto
    net/socket.c:2198 [inline] __x64_sys_sendto+0xe0/0x1b0 net/socket.c:2198 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0x40/0x110 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x63/0x6b RIP: 0033:0x7f8692032aa9 Code: 28 00 00 00 75 05 48 83 c4 28 c3
    e8 d1 19 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0
    ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007fff8d685418 EFLAGS: 00000246
    ORIG_RAX: 000000000000002c RAX: ffffffffffffffda RBX: 0000000000000003 RCX: 00007f8692032aa9 RDX:
    0000000000010048 RSI: 00000000200000c0 RDI: 0000000000000003 RBP: 00000000000f4240 R08: 0000000020000540
    R09: 0000000000000014 R10: 0000000000000000 R11: 0000000000000246 R12: 00007fff8d685480 R13:
    0000000000000001 R14: 00007fff8d685480 R15: 0000000000000003 </TASK> Modules linked in: ---[ end trace
    0000000000000000 ]--- RIP: 0010:skb_segment+0x181d/0x3f30 net/core/skbuff.c:4551 Code: 83 e3 02 e9 fb ed
    ff ff e8 90 68 1c f9 48 8b 84 24 f8 00 00 00 48 8d 78 70 48 b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1 ea
    03 <0f> b6 04 02 84 c0 74 08 3c 03 0f 8e 8a 21 00 00 48 8b 84 24 f8 00 RSP: 0018:ffffc900043473d0 EFLAGS:
    00010202 RAX: dffffc0000000000 RBX: 0000000000010046 RCX: ffffffff886b1597 RDX: 000000000000000e RSI:
    ffffffff886b2520 RDI: 0000000000000070 RBP: ffffc90004347578 R0 ---truncated--- (CVE-2023-52435)

  - In the Linux kernel, the following vulnerability has been resolved: uio: Fix use-after-free in uio_open
    core-1 core-2 ------------------------------------------------------- uio_unregister_device uio_open idev
    = idr_find() device_unregister(&idev->dev) put_device(&idev->dev) uio_device_release
    get_device(&idev->dev) kfree(idev) uio_free_minor(minor) uio_release put_device(&idev->dev) kfree(idev)
    ------------------------------------------------------- In the core-1 uio_unregister_device(), the
    device_unregister will kfree idev when the idev->dev kobject ref is 1. But after core-1 device_unregister,
    put_device and before doing kfree, the core-2 may get_device. Then: 1. After core-1 kfree idev, the core-2
    will do use-after-free for idev. 2. When core-2 do uio_release and put_device, the idev will be double
    freed. To address this issue, we can get idev atomic & inc idev reference with minor_lock.
    (CVE-2023-52439)

  - An out-of-bounds access vulnerability involving netfilter was reported and fixed as: f1082dd31fe4
    (netfilter: nf_tables: Reject tables of unsupported family); While creating a new netfilter table, lack of
    a safeguard against invalid nf_tables family (pf) values within `nf_tables_newtable` function enables an
    attacker to achieve out-of-bounds access. (CVE-2023-6040)

  - An out-of-bounds read vulnerability was found in the NVMe-oF/TCP subsystem in the Linux kernel. This issue
    may allow a remote attacker to send a crafted TCP packet, triggering a heap-based buffer overflow that
    results in kmalloc data being printed and potentially leaked to the kernel ring buffer (dmesg).
    (CVE-2023-6121)

  - A memory leak problem was found in ctnetlink_create_conntrack in net/netfilter/nf_conntrack_netlink.c in
    the Linux Kernel. This issue may allow a local attacker with CAP_NET_ADMIN privileges to cause a denial of
    service (DoS) attack due to a refcount overflow. (CVE-2023-7192)

  - A vulnerability was found in vhost_new_msg in drivers/vhost/vhost.c in the Linux kernel, which does not
    properly initialize memory in messages passed between virtual guests and the host operating system in the
    vhost/vhost.c:vhost_new_msg() function. This issue can allow local privileged users to read some kernel
    memory contents when reading from the /dev/vhost-net device file. (CVE-2024-0340)

  - An out-of-bounds memory read flaw was found in receive_encrypted_standard in fs/smb/client/smb2ops.c in
    the SMB Client sub-component in the Linux Kernel. This issue occurs due to integer underflow on the memcpy
    length, leading to a denial of service. (CVE-2024-0565)

  - A flaw was found in the Netfilter subsystem in the Linux kernel. The issue is in the nft_byteorder_eval()
    function, where the code iterates through a loop and writes to the `dst` array. On each iteration, 8 bytes
    are written, but `dst` is an array of u32, so each element only has space for 4 bytes. That means every
    iteration overwrites part of the previous element corrupting this array of u32. This flaw allows a local
    user to cause a denial of service or potentially break NetFilter functionality. (CVE-2024-0607)

  - A denial of service vulnerability due to a deadlock was found in sctp_auto_asconf_init in
    net/sctp/socket.c in the Linux kernel's SCTP subsystem. This flaw allows guests with local user privileges
    to trigger a deadlock and potentially crash the system. (CVE-2024-0639)

  - A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation. The nft_verdict_init() function allows positive values as drop error
    within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when
    NF_DROP is issued with a drop error which resembles NF_ACCEPT. We recommend upgrading past commit
    f342de4e2f33e0e39165d8639387aa6c19dff660. (CVE-2024-1086)

  - When a router encounters an IPv6 packet too big to transmit to the next-hop, it returns an ICMP6 'Packet
    Too Big' (PTB) message to the sender. The sender caches this updated Maximum Transmission Unit (MTU) so it
    knows not to exceed this value when subsequently routing to the same host. (CVE-2023-52340)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1488
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b41b685");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0565");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-1086");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.19.90-vhulk2103.1.0.h1185.eulerosv2r9",
  "kernel-tools-4.19.90-vhulk2103.1.0.h1185.eulerosv2r9",
  "kernel-tools-libs-4.19.90-vhulk2103.1.0.h1185.eulerosv2r9",
  "python3-perf-4.19.90-vhulk2103.1.0.h1185.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
