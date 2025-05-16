#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228678);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-44999");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-44999");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: gtp: pull network headers in
    gtp_dev_xmit() syzbot/KMSAN reported use of uninit-value in get_dev_xmit() [1] We must make sure the IPv4
    or Ipv6 header is pulled in skb->head before accessing fields in them. Use pskb_inet_may_pull() to fix
    this issue. [1] BUG: KMSAN: uninit-value in ipv6_pdp_find drivers/net/gtp.c:220 [inline] BUG: KMSAN:
    uninit-value in gtp_build_skb_ip6 drivers/net/gtp.c:1229 [inline] BUG: KMSAN: uninit-value in
    gtp_dev_xmit+0x1424/0x2540 drivers/net/gtp.c:1281 ipv6_pdp_find drivers/net/gtp.c:220 [inline]
    gtp_build_skb_ip6 drivers/net/gtp.c:1229 [inline] gtp_dev_xmit+0x1424/0x2540 drivers/net/gtp.c:1281
    __netdev_start_xmit include/linux/netdevice.h:4913 [inline] netdev_start_xmit
    include/linux/netdevice.h:4922 [inline] xmit_one net/core/dev.c:3580 [inline]
    dev_hard_start_xmit+0x247/0xa20 net/core/dev.c:3596 __dev_queue_xmit+0x358c/0x5610 net/core/dev.c:4423
    dev_queue_xmit include/linux/netdevice.h:3105 [inline] packet_xmit+0x9c/0x6c0 net/packet/af_packet.c:276
    packet_snd net/packet/af_packet.c:3145 [inline] packet_sendmsg+0x90e3/0xa3a0 net/packet/af_packet.c:3177
    sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg+0x30f/0x380 net/socket.c:745
    __sys_sendto+0x685/0x830 net/socket.c:2204 __do_sys_sendto net/socket.c:2216 [inline] __se_sys_sendto
    net/socket.c:2212 [inline] __x64_sys_sendto+0x125/0x1d0 net/socket.c:2212 x64_sys_call+0x3799/0x3c10
    arch/x86/include/generated/asm/syscalls_64.h:45 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f Uninit was
    created at: slab_post_alloc_hook mm/slub.c:3994 [inline] slab_alloc_node mm/slub.c:4037 [inline]
    kmem_cache_alloc_node_noprof+0x6bf/0xb80 mm/slub.c:4080 kmalloc_reserve+0x13d/0x4a0 net/core/skbuff.c:583
    __alloc_skb+0x363/0x7b0 net/core/skbuff.c:674 alloc_skb include/linux/skbuff.h:1320 [inline]
    alloc_skb_with_frags+0xc8/0xbf0 net/core/skbuff.c:6526 sock_alloc_send_pskb+0xa81/0xbf0
    net/core/sock.c:2815 packet_alloc_skb net/packet/af_packet.c:2994 [inline] packet_snd
    net/packet/af_packet.c:3088 [inline] packet_sendmsg+0x749c/0xa3a0 net/packet/af_packet.c:3177
    sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg+0x30f/0x380 net/socket.c:745
    __sys_sendto+0x685/0x830 net/socket.c:2204 __do_sys_sendto net/socket.c:2216 [inline] __se_sys_sendto
    net/socket.c:2212 [inline] __x64_sys_sendto+0x125/0x1d0 net/socket.c:2212 x64_sys_call+0x3799/0x3c10
    arch/x86/include/generated/asm/syscalls_64.h:45 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f CPU: 0 UID: 0
    PID: 7115 Comm: syz.1.515 Not tainted 6.11.0-rc1-syzkaller-00043-g94ede2a3e913 #0 Hardware name: Google
    Google Compute Engine/Google Compute Engine, BIOS Google 06/27/2024 (CVE-2024-44999)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44999");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

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
    "name": "linux-azure-fde",
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
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "linux-azure-fde-5.15",
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
        "os_version": "20.04"
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
