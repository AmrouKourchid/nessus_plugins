#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228088);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26863");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26863");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: hsr: Fix uninit-value access in
    hsr_get_node() KMSAN reported the following uninit-value access issue [1]:
    ===================================================== BUG: KMSAN: uninit-value in hsr_get_node+0xa2e/0xa40
    net/hsr/hsr_framereg.c:246 hsr_get_node+0xa2e/0xa40 net/hsr/hsr_framereg.c:246 fill_frame_info
    net/hsr/hsr_forward.c:577 [inline] hsr_forward_skb+0xe12/0x30e0 net/hsr/hsr_forward.c:615
    hsr_dev_xmit+0x1a1/0x270 net/hsr/hsr_device.c:223 __netdev_start_xmit include/linux/netdevice.h:4940
    [inline] netdev_start_xmit include/linux/netdevice.h:4954 [inline] xmit_one net/core/dev.c:3548 [inline]
    dev_hard_start_xmit+0x247/0xa10 net/core/dev.c:3564 __dev_queue_xmit+0x33b8/0x5130 net/core/dev.c:4349
    dev_queue_xmit include/linux/netdevice.h:3134 [inline] packet_xmit+0x9c/0x6b0 net/packet/af_packet.c:276
    packet_snd net/packet/af_packet.c:3087 [inline] packet_sendmsg+0x8b1d/0x9f30 net/packet/af_packet.c:3119
    sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745 [inline]
    __sys_sendto+0x735/0xa10 net/socket.c:2191 __do_sys_sendto net/socket.c:2203 [inline] __se_sys_sendto
    net/socket.c:2199 [inline] __x64_sys_sendto+0x125/0x1c0 net/socket.c:2199 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0x6d/0x140 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x63/0x6b Uninit was created at: slab_post_alloc_hook+0x129/0xa70
    mm/slab.h:768 slab_alloc_node mm/slub.c:3478 [inline] kmem_cache_alloc_node+0x5e9/0xb10 mm/slub.c:3523
    kmalloc_reserve+0x13d/0x4a0 net/core/skbuff.c:560 __alloc_skb+0x318/0x740 net/core/skbuff.c:651 alloc_skb
    include/linux/skbuff.h:1286 [inline] alloc_skb_with_frags+0xc8/0xbd0 net/core/skbuff.c:6334
    sock_alloc_send_pskb+0xa80/0xbf0 net/core/sock.c:2787 packet_alloc_skb net/packet/af_packet.c:2936
    [inline] packet_snd net/packet/af_packet.c:3030 [inline] packet_sendmsg+0x70e8/0x9f30
    net/packet/af_packet.c:3119 sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745
    [inline] __sys_sendto+0x735/0xa10 net/socket.c:2191 __do_sys_sendto net/socket.c:2203 [inline]
    __se_sys_sendto net/socket.c:2199 [inline] __x64_sys_sendto+0x125/0x1c0 net/socket.c:2199 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0x6d/0x140 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x63/0x6b CPU: 1 PID: 5033 Comm: syz-executor334 Not tainted
    6.7.0-syzkaller-00562-g9f8413c4a66f #0 Hardware name: Google Google Compute Engine/Google Compute Engine,
    BIOS Google 11/17/2023 ===================================================== If the packet type ID field
    in the Ethernet header is either ETH_P_PRP or ETH_P_HSR, but it is not followed by an HSR tag,
    hsr_get_skb_sequence_nr() reads an invalid value as a sequence number. This causes the above issue. This
    patch fixes the issue by returning NULL if the Ethernet header is not followed by an HSR tag.
    (CVE-2024-26863)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26863");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
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
