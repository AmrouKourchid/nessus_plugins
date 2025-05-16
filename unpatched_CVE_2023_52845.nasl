#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225817);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52845");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52845");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tipc: Change nla_policy for bearer-
    related names to NLA_NUL_STRING syzbot reported the following uninit-value access issue [1]:
    ===================================================== BUG: KMSAN: uninit-value in strlen lib/string.c:418
    [inline] BUG: KMSAN: uninit-value in strstr+0xb8/0x2f0 lib/string.c:756 strlen lib/string.c:418 [inline]
    strstr+0xb8/0x2f0 lib/string.c:756 tipc_nl_node_reset_link_stats+0x3ea/0xb50 net/tipc/node.c:2595
    genl_family_rcv_msg_doit net/netlink/genetlink.c:971 [inline] genl_family_rcv_msg
    net/netlink/genetlink.c:1051 [inline] genl_rcv_msg+0x11ec/0x1290 net/netlink/genetlink.c:1066
    netlink_rcv_skb+0x371/0x650 net/netlink/af_netlink.c:2545 genl_rcv+0x40/0x60 net/netlink/genetlink.c:1075
    netlink_unicast_kernel net/netlink/af_netlink.c:1342 [inline] netlink_unicast+0xf47/0x1250
    net/netlink/af_netlink.c:1368 netlink_sendmsg+0x1238/0x13d0 net/netlink/af_netlink.c:1910
    sock_sendmsg_nosec net/socket.c:730 [inline] sock_sendmsg net/socket.c:753 [inline]
    ____sys_sendmsg+0x9c2/0xd60 net/socket.c:2541 ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2595 __sys_sendmsg
    net/socket.c:2624 [inline] __do_sys_sendmsg net/socket.c:2633 [inline] __se_sys_sendmsg net/socket.c:2631
    [inline] __x64_sys_sendmsg+0x307/0x490 net/socket.c:2631 do_syscall_x64 arch/x86/entry/common.c:50
    [inline] do_syscall_64+0x41/0xc0 arch/x86/entry/common.c:80 entry_SYSCALL_64_after_hwframe+0x63/0xcd
    Uninit was created at: slab_post_alloc_hook+0x12f/0xb70 mm/slab.h:767 slab_alloc_node mm/slub.c:3478
    [inline] kmem_cache_alloc_node+0x577/0xa80 mm/slub.c:3523 kmalloc_reserve+0x13d/0x4a0
    net/core/skbuff.c:559 __alloc_skb+0x318/0x740 net/core/skbuff.c:650 alloc_skb include/linux/skbuff.h:1286
    [inline] netlink_alloc_large_skb net/netlink/af_netlink.c:1214 [inline] netlink_sendmsg+0xb34/0x13d0
    net/netlink/af_netlink.c:1885 sock_sendmsg_nosec net/socket.c:730 [inline] sock_sendmsg net/socket.c:753
    [inline] ____sys_sendmsg+0x9c2/0xd60 net/socket.c:2541 ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2595
    __sys_sendmsg net/socket.c:2624 [inline] __do_sys_sendmsg net/socket.c:2633 [inline] __se_sys_sendmsg
    net/socket.c:2631 [inline] __x64_sys_sendmsg+0x307/0x490 net/socket.c:2631 do_syscall_x64
    arch/x86/entry/common.c:50 [inline] do_syscall_64+0x41/0xc0 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x63/0xcd TIPC bearer-related names including link names must be null-
    terminated strings. If a link name which is not null-terminated is passed through netlink, strstr() and
    similar functions can cause buffer overrun. This causes the above issue. This patch changes the nla_policy
    for bearer-related names from NLA_STRING to NLA_NUL_STRING. This resolves the issue by ensuring that only
    null-terminated strings are accepted as bearer-related names. syzbot reported similar uninit-value issue
    related to bearer names [2]. The root cause of this issue is that a non-null-terminated bearer name was
    passed. This patch also resolved this issue. (CVE-2023-52845)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52845");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
    "name": "kernel",
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
