#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230688);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2025-21677");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2025-21677");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: pfcp: Destroy device along with udp
    socket's netns dismantle. pfcp_newlink() links the device to a list in dev_net(dev) instead of net, where
    a udp tunnel socket is created. Even when net is removed, the device stays alive on dev_net(dev). Then,
    removing net triggers the splat below. [0] In this example, pfcp0 is created in ns2, but the udp socket is
    created in ns1. ip netns add ns1 ip netns add ns2 ip -n ns1 link add netns ns2 name pfcp0 type pfcp ip
    netns del ns1 Let's link the device to the socket's netns instead. Now, pfcp_net_exit() needs another
    netdev iteration to remove all pfcp devices in the netns. pfcp_dev_list is not used under RCU, so the list
    API is converted to the non-RCU variant. pfcp_net_exit() can be converted to .exit_batch_rtnl() in net-
    next. [0]: ref_tracker: net notrefcnt@00000000128b34dc has 1/1 users at sk_alloc
    (./include/net/net_namespace.h:345 net/core/sock.c:2236) inet_create (net/ipv4/af_inet.c:326
    net/ipv4/af_inet.c:252) __sock_create (net/socket.c:1558) udp_sock_create4 (net/ipv4/udp_tunnel_core.c:18)
    pfcp_create_sock (drivers/net/pfcp.c:168) pfcp_newlink (drivers/net/pfcp.c:182 drivers/net/pfcp.c:197)
    rtnl_newlink (net/core/rtnetlink.c:3786 net/core/rtnetlink.c:3897 net/core/rtnetlink.c:4012)
    rtnetlink_rcv_msg (net/core/rtnetlink.c:6922) netlink_rcv_skb (net/netlink/af_netlink.c:2542)
    netlink_unicast (net/netlink/af_netlink.c:1321 net/netlink/af_netlink.c:1347) netlink_sendmsg
    (net/netlink/af_netlink.c:1891) ____sys_sendmsg (net/socket.c:711 net/socket.c:726 net/socket.c:2583)
    ___sys_sendmsg (net/socket.c:2639) __sys_sendmsg (net/socket.c:2669) do_syscall_64
    (arch/x86/entry/common.c:52 arch/x86/entry/common.c:83) entry_SYSCALL_64_after_hwframe
    (arch/x86/entry/entry_64.S:130) WARNING: CPU: 1 PID: 11 at lib/ref_tracker.c:179 ref_tracker_dir_exit
    (lib/ref_tracker.c:179) Modules linked in: CPU: 1 UID: 0 PID: 11 Comm: kworker/u16:0 Not tainted
    6.13.0-rc5-00147-g4c1224501e9d #5 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
    rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014 Workqueue: netns cleanup_net RIP:
    0010:ref_tracker_dir_exit (lib/ref_tracker.c:179) Code: 00 00 00 fc ff df 4d 8b 26 49 bd 00 01 00 00 00 00
    ad de 4c 39 f5 0f 85 df 00 00 00 48 8b 74 24 08 48 89 df e8 a5 cc 12 02 90 <0f> 0b 90 48 8d 6b 44 be 04 00
    00 00 48 89 ef e8 80 de 67 ff 48 89 RSP: 0018:ff11000007f3fb60 EFLAGS: 00010286 RAX: 00000000000020ef RBX:
    ff1100000d6481e0 RCX: 1ffffffff0e40d82 RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffff8423ee3c
    RBP: ff1100000d648230 R08: 0000000000000001 R09: fffffbfff0e395af R10: 0000000000000001 R11:
    0000000000000000 R12: ff1100000d648230 R13: dead000000000100 R14: ff1100000d648230 R15: dffffc0000000000
    FS: 0000000000000000(0000) GS:ff1100006ce80000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 CR2: 00005620e1363990 CR3: 000000000eeb2002 CR4: 0000000000771ef0 DR0:
    0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe07f0
    DR7: 0000000000000400 PKRU: 55555554 Call Trace: <TASK> ? __warn (kernel/panic.c:748) ?
    ref_tracker_dir_exit (lib/ref_tracker.c:179) ? report_bug (lib/bug.c:201 lib/bug.c:219) ? handle_bug
    (arch/x86/kernel/traps.c:285) ? exc_invalid_op (arch/x86/kernel/traps.c:309 (discriminator 1)) ?
    asm_exc_invalid_op (./arch/x86/include/asm/idtentry.h:621) ? _raw_spin_unlock_irqrestore
    (./arch/x86/include/asm/irqflags.h:42 ./arch/x86/include/asm/irqflags.h:97
    ./arch/x86/include/asm/irqflags.h:155 ./include/linux/spinlock_api_smp.h:151
    kernel/locking/spinlock.c:194) ? ref_tracker_dir_exit (lib/ref_tracker.c:179) ? __pfx_ref_tracker_dir_exit
    (lib/ref_tracker.c:158) ? kfree (mm/slub.c:4613 mm/slub.c:4761) net_free (net/core/net_namespace.c:476
    net/core/net_namespace.c:467) cleanup_net (net/cor ---truncated--- (CVE-2025-21677)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21677");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": [
     "linux-aws-cloud-tools-6.11.0-1004",
     "linux-aws-headers-6.11.0-1004",
     "linux-aws-tools-6.11.0-1004",
     "linux-azure-cloud-tools-6.11.0-1004",
     "linux-azure-headers-6.11.0-1004",
     "linux-azure-tools-6.11.0-1004",
     "linux-bpf-dev",
     "linux-buildinfo-6.11.0-1003-gcp",
     "linux-buildinfo-6.11.0-1004-aws",
     "linux-buildinfo-6.11.0-1004-azure",
     "linux-buildinfo-6.11.0-1004-lowlatency",
     "linux-buildinfo-6.11.0-1004-lowlatency-64k",
     "linux-buildinfo-6.11.0-1004-raspi",
     "linux-buildinfo-6.11.0-1006-oracle",
     "linux-buildinfo-6.11.0-1006-oracle-64k",
     "linux-buildinfo-6.11.0-8-generic",
     "linux-cloud-tools-6.11.0-1004-aws",
     "linux-cloud-tools-6.11.0-1004-azure",
     "linux-cloud-tools-6.11.0-1004-lowlatency",
     "linux-cloud-tools-6.11.0-1004-lowlatency-64k",
     "linux-cloud-tools-6.11.0-1006-oracle",
     "linux-cloud-tools-6.11.0-1006-oracle-64k",
     "linux-cloud-tools-6.11.0-8",
     "linux-cloud-tools-6.11.0-8-generic",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-gcp-headers-6.11.0-1003",
     "linux-gcp-tools-6.11.0-1003",
     "linux-headers-6.11.0-1003-gcp",
     "linux-headers-6.11.0-1004-aws",
     "linux-headers-6.11.0-1004-azure",
     "linux-headers-6.11.0-1004-lowlatency",
     "linux-headers-6.11.0-1004-lowlatency-64k",
     "linux-headers-6.11.0-1004-raspi",
     "linux-headers-6.11.0-1006-oracle",
     "linux-headers-6.11.0-1006-oracle-64k",
     "linux-headers-6.11.0-8",
     "linux-headers-6.11.0-8-generic",
     "linux-headers-6.11.0-8-generic-64k",
     "linux-image-6.11.0-1004-raspi",
     "linux-image-6.11.0-1004-raspi-dbgsym",
     "linux-image-6.11.0-8-generic",
     "linux-image-6.11.0-8-generic-dbgsym",
     "linux-image-unsigned-6.11.0-1003-gcp",
     "linux-image-unsigned-6.11.0-1003-gcp-dbgsym",
     "linux-image-unsigned-6.11.0-1004-aws",
     "linux-image-unsigned-6.11.0-1004-aws-dbgsym",
     "linux-image-unsigned-6.11.0-1004-azure",
     "linux-image-unsigned-6.11.0-1004-azure-dbgsym",
     "linux-image-unsigned-6.11.0-1004-lowlatency",
     "linux-image-unsigned-6.11.0-1004-lowlatency-64k",
     "linux-image-unsigned-6.11.0-1004-lowlatency-64k-dbgsym",
     "linux-image-unsigned-6.11.0-1004-lowlatency-dbgsym",
     "linux-image-unsigned-6.11.0-1006-oracle",
     "linux-image-unsigned-6.11.0-1006-oracle-64k",
     "linux-image-unsigned-6.11.0-1006-oracle-64k-dbgsym",
     "linux-image-unsigned-6.11.0-1006-oracle-dbgsym",
     "linux-image-unsigned-6.11.0-8-generic",
     "linux-image-unsigned-6.11.0-8-generic-64k",
     "linux-image-unsigned-6.11.0-8-generic-64k-dbgsym",
     "linux-image-unsigned-6.11.0-8-generic-dbgsym",
     "linux-lib-rust-6.11.0-8-generic",
     "linux-lib-rust-6.11.0-8-generic-64k",
     "linux-libc-dev",
     "linux-lowlatency-cloud-tools-6.11.0-1004",
     "linux-lowlatency-headers-6.11.0-1004",
     "linux-lowlatency-lib-rust-6.11.0-1004-lowlatency",
     "linux-lowlatency-lib-rust-6.11.0-1004-lowlatency-64k",
     "linux-lowlatency-tools-6.11.0-1004",
     "linux-modules-6.11.0-1003-gcp",
     "linux-modules-6.11.0-1004-aws",
     "linux-modules-6.11.0-1004-azure",
     "linux-modules-6.11.0-1004-lowlatency",
     "linux-modules-6.11.0-1004-lowlatency-64k",
     "linux-modules-6.11.0-1004-raspi",
     "linux-modules-6.11.0-1006-oracle",
     "linux-modules-6.11.0-1006-oracle-64k",
     "linux-modules-6.11.0-8-generic",
     "linux-modules-6.11.0-8-generic-64k",
     "linux-modules-extra-6.11.0-1003-gcp",
     "linux-modules-extra-6.11.0-1004-aws",
     "linux-modules-extra-6.11.0-1004-azure",
     "linux-modules-extra-6.11.0-1004-lowlatency",
     "linux-modules-extra-6.11.0-1004-lowlatency-64k",
     "linux-modules-extra-6.11.0-1006-oracle",
     "linux-modules-extra-6.11.0-1006-oracle-64k",
     "linux-modules-extra-6.11.0-8-generic",
     "linux-modules-extra-6.11.0-8-generic-64k",
     "linux-modules-ipu6-6.11.0-8-generic",
     "linux-modules-ipu7-6.11.0-8-generic",
     "linux-modules-iwlwifi-6.11.0-1004-azure",
     "linux-modules-iwlwifi-6.11.0-1004-lowlatency",
     "linux-modules-iwlwifi-6.11.0-1004-raspi",
     "linux-modules-iwlwifi-6.11.0-8-generic",
     "linux-modules-usbio-6.11.0-8-generic",
     "linux-modules-vision-6.11.0-8-generic",
     "linux-oracle-headers-6.11.0-1006",
     "linux-oracle-tools-6.11.0-1006",
     "linux-raspi-headers-6.11.0-1004",
     "linux-raspi-tools-6.11.0-1004",
     "linux-realtime",
     "linux-riscv-headers-6.11.0-8",
     "linux-riscv-tools-6.11.0-8",
     "linux-source-6.11.0",
     "linux-tools-6.11.0-1003-gcp",
     "linux-tools-6.11.0-1004-aws",
     "linux-tools-6.11.0-1004-azure",
     "linux-tools-6.11.0-1004-lowlatency",
     "linux-tools-6.11.0-1004-lowlatency-64k",
     "linux-tools-6.11.0-1004-raspi",
     "linux-tools-6.11.0-1006-oracle",
     "linux-tools-6.11.0-1006-oracle-64k",
     "linux-tools-6.11.0-8",
     "linux-tools-6.11.0-8-generic",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "24.10"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-hwe-6.11",
     "linux-lowlatency-hwe-6.11",
     "linux-oem-6.11"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "24.04"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
