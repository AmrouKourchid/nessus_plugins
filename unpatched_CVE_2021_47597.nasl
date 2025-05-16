#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230103);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47597");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47597");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: inet_diag: fix kernel-infoleak for UDP
    sockets KMSAN reported a kernel-infoleak [1], that can exploited by unpriv users. After analysis it turned
    out UDP was not initializing r->idiag_expires. Other users of inet_sk_diag_fill() might make the same
    mistake in the future, so fix this in inet_sk_diag_fill(). [1] BUG: KMSAN: kernel-infoleak in
    instrument_copy_to_user include/linux/instrumented.h:121 [inline] BUG: KMSAN: kernel-infoleak in copyout
    lib/iov_iter.c:156 [inline] BUG: KMSAN: kernel-infoleak in _copy_to_iter+0x69d/0x25c0 lib/iov_iter.c:670
    instrument_copy_to_user include/linux/instrumented.h:121 [inline] copyout lib/iov_iter.c:156 [inline]
    _copy_to_iter+0x69d/0x25c0 lib/iov_iter.c:670 copy_to_iter include/linux/uio.h:155 [inline]
    simple_copy_to_iter+0xf3/0x140 net/core/datagram.c:519 __skb_datagram_iter+0x2cb/0x1280
    net/core/datagram.c:425 skb_copy_datagram_iter+0xdc/0x270 net/core/datagram.c:533 skb_copy_datagram_msg
    include/linux/skbuff.h:3657 [inline] netlink_recvmsg+0x660/0x1c60 net/netlink/af_netlink.c:1974
    sock_recvmsg_nosec net/socket.c:944 [inline] sock_recvmsg net/socket.c:962 [inline]
    sock_read_iter+0x5a9/0x630 net/socket.c:1035 call_read_iter include/linux/fs.h:2156 [inline] new_sync_read
    fs/read_write.c:400 [inline] vfs_read+0x1631/0x1980 fs/read_write.c:481 ksys_read+0x28c/0x520
    fs/read_write.c:619 __do_sys_read fs/read_write.c:629 [inline] __se_sys_read fs/read_write.c:627 [inline]
    __x64_sys_read+0xdb/0x120 fs/read_write.c:627 do_syscall_x64 arch/x86/entry/common.c:51 [inline]
    do_syscall_64+0x54/0xd0 arch/x86/entry/common.c:82 entry_SYSCALL_64_after_hwframe+0x44/0xae Uninit was
    created at: slab_post_alloc_hook mm/slab.h:524 [inline] slab_alloc_node mm/slub.c:3251 [inline]
    __kmalloc_node_track_caller+0xe0c/0x1510 mm/slub.c:4974 kmalloc_reserve net/core/skbuff.c:354 [inline]
    __alloc_skb+0x545/0xf90 net/core/skbuff.c:426 alloc_skb include/linux/skbuff.h:1126 [inline]
    netlink_dump+0x3d5/0x16a0 net/netlink/af_netlink.c:2245 __netlink_dump_start+0xd1c/0xee0
    net/netlink/af_netlink.c:2370 netlink_dump_start include/linux/netlink.h:254 [inline]
    inet_diag_handler_cmd+0x2e7/0x400 net/ipv4/inet_diag.c:1343 sock_diag_rcv_msg+0x24a/0x620
    netlink_rcv_skb+0x447/0x800 net/netlink/af_netlink.c:2491 sock_diag_rcv+0x63/0x80 net/core/sock_diag.c:276
    netlink_unicast_kernel net/netlink/af_netlink.c:1319 [inline] netlink_unicast+0x1095/0x1360
    net/netlink/af_netlink.c:1345 netlink_sendmsg+0x16f3/0x1870 net/netlink/af_netlink.c:1916
    sock_sendmsg_nosec net/socket.c:704 [inline] sock_sendmsg net/socket.c:724 [inline]
    sock_write_iter+0x594/0x690 net/socket.c:1057 do_iter_readv_writev+0xa7f/0xc70 do_iter_write+0x52c/0x1500
    fs/read_write.c:851 vfs_writev fs/read_write.c:924 [inline] do_writev+0x63f/0xe30 fs/read_write.c:967
    __do_sys_writev fs/read_write.c:1040 [inline] __se_sys_writev fs/read_write.c:1037 [inline]
    __x64_sys_writev+0xe5/0x120 fs/read_write.c:1037 do_syscall_x64 arch/x86/entry/common.c:51 [inline]
    do_syscall_64+0x54/0xd0 arch/x86/entry/common.c:82 entry_SYSCALL_64_after_hwframe+0x44/0xae Bytes 68-71 of
    312 are uninitialized Memory access of size 312 starts at ffff88812ab54000 Data copied to user address
    0000000020001440 CPU: 1 PID: 6365 Comm: syz-executor801 Not tainted 5.16.0-rc3-syzkaller #0 Hardware name:
    Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011 (CVE-2021-47597)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47597");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
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
    "name": [
     "kernel",
     "kernel-rt"
    ],
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
        "os_version": "8"
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
