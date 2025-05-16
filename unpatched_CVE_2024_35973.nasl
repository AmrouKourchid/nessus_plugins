#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229397);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35973");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35973");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: geneve: fix header validation in
    geneve[6]_xmit_skb syzbot is able to trigger an uninit-value in geneve_xmit() [1] Problem : While most ip
    tunnel helpers (like ip_tunnel_get_dsfield()) uses skb_protocol(skb, true), pskb_inet_may_pull() is only
    using skb->protocol. If anything else than ETH_P_IPV6 or ETH_P_IP is found in skb->protocol,
    pskb_inet_may_pull() does nothing at all. If a vlan tag was provided by the caller (af_packet in the
    syzbot case), the network header might not point to the correct location, and skb linear part could be
    smaller than expected. Add skb_vlan_inet_prepare() to perform a complete mac validation. Use this in
    geneve for the moment, I suspect we need to adopt this more broadly. v4 - Jakub reported v3 broke
    l2_tos_ttl_inherit.sh selftest - Only call __vlan_get_protocol() for vlan types. v2,v3 - Addressed Sabrina
    comments on v1 and v2 [1] BUG: KMSAN: uninit-value in geneve_xmit_skb drivers/net/geneve.c:910 [inline]
    BUG: KMSAN: uninit-value in geneve_xmit+0x302d/0x5420 drivers/net/geneve.c:1030 geneve_xmit_skb
    drivers/net/geneve.c:910 [inline] geneve_xmit+0x302d/0x5420 drivers/net/geneve.c:1030 __netdev_start_xmit
    include/linux/netdevice.h:4903 [inline] netdev_start_xmit include/linux/netdevice.h:4917 [inline] xmit_one
    net/core/dev.c:3531 [inline] dev_hard_start_xmit+0x247/0xa20 net/core/dev.c:3547
    __dev_queue_xmit+0x348d/0x52c0 net/core/dev.c:4335 dev_queue_xmit include/linux/netdevice.h:3091 [inline]
    packet_xmit+0x9c/0x6c0 net/packet/af_packet.c:276 packet_snd net/packet/af_packet.c:3081 [inline]
    packet_sendmsg+0x8bb0/0x9ef0 net/packet/af_packet.c:3113 sock_sendmsg_nosec net/socket.c:730 [inline]
    __sock_sendmsg+0x30f/0x380 net/socket.c:745 __sys_sendto+0x685/0x830 net/socket.c:2191 __do_sys_sendto
    net/socket.c:2203 [inline] __se_sys_sendto net/socket.c:2199 [inline] __x64_sys_sendto+0x125/0x1d0
    net/socket.c:2199 do_syscall_64+0xd5/0x1f0 entry_SYSCALL_64_after_hwframe+0x6d/0x75 Uninit was created at:
    slab_post_alloc_hook mm/slub.c:3804 [inline] slab_alloc_node mm/slub.c:3845 [inline]
    kmem_cache_alloc_node+0x613/0xc50 mm/slub.c:3888 kmalloc_reserve+0x13d/0x4a0 net/core/skbuff.c:577
    __alloc_skb+0x35b/0x7a0 net/core/skbuff.c:668 alloc_skb include/linux/skbuff.h:1318 [inline]
    alloc_skb_with_frags+0xc8/0xbf0 net/core/skbuff.c:6504 sock_alloc_send_pskb+0xa81/0xbf0
    net/core/sock.c:2795 packet_alloc_skb net/packet/af_packet.c:2930 [inline] packet_snd
    net/packet/af_packet.c:3024 [inline] packet_sendmsg+0x722d/0x9ef0 net/packet/af_packet.c:3113
    sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg+0x30f/0x380 net/socket.c:745
    __sys_sendto+0x685/0x830 net/socket.c:2191 __do_sys_sendto net/socket.c:2203 [inline] __se_sys_sendto
    net/socket.c:2199 [inline] __x64_sys_sendto+0x125/0x1d0 net/socket.c:2199 do_syscall_64+0xd5/0x1f0
    entry_SYSCALL_64_after_hwframe+0x6d/0x75 CPU: 0 PID: 5033 Comm: syz-executor346 Not tainted
    6.9.0-rc1-syzkaller-00005-g928a87efa423 #0 Hardware name: Google Google Compute Engine/Google Compute
    Engine, BIOS Google 02/29/2024 (CVE-2024-35973)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35973");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

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
    "name": "kernel-rt",
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "9"
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
