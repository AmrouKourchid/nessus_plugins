#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229258);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41041");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41041");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: udp: Set SOCK_RCU_FREE earlier in
    udp_lib_get_port(). syzkaller triggered the warning [0] in udp_v4_early_demux(). In
    udp_v[46]_early_demux() and sk_lookup(), we do not touch the refcount of the looked-up sk and use
    sock_pfree() as skb->destructor, so we check SOCK_RCU_FREE to ensure that the sk is safe to access during
    the RCU grace period. Currently, SOCK_RCU_FREE is flagged for a bound socket after being put into the hash
    table. Moreover, the SOCK_RCU_FREE check is done too early in udp_v[46]_early_demux() and sk_lookup(), so
    there could be a small race window: CPU1 CPU2 ---- ---- udp_v4_early_demux() udp_lib_get_port() | |-
    hlist_add_head_rcu() |- sk = __udp4_lib_demux_lookup() | |- DEBUG_NET_WARN_ON_ONCE(sk_is_refcounted(sk));
    `- sock_set_flag(sk, SOCK_RCU_FREE) We had the same bug in TCP and fixed it in commit 871019b22d1b (net:
    set SOCK_RCU_FREE before inserting socket into hashtable). Let's apply the same fix for UDP. [0]:
    WARNING: CPU: 0 PID: 11198 at net/ipv4/udp.c:2599 udp_v4_early_demux+0x481/0xb70 net/ipv4/udp.c:2599
    Modules linked in: CPU: 0 PID: 11198 Comm: syz-executor.1 Not tainted 6.9.0-g93bda33046e7 #13 Hardware
    name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014
    RIP: 0010:udp_v4_early_demux+0x481/0xb70 net/ipv4/udp.c:2599 Code: c5 7a 15 fe bb 01 00 00 00 44 89 e9 31
    ff d3 e3 81 e3 bf ef ff ff 89 de e8 2c 74 15 fe 85 db 0f 85 02 06 00 00 e8 9f 7a 15 fe <0f> 0b e8 98 7a 15
    fe 49 8d 7e 60 e8 4f 39 2f fe 49 c7 46 60 20 52 RSP: 0018:ffffc9000ce3fa58 EFLAGS: 00010293 RAX:
    0000000000000000 RBX: 0000000000000000 RCX: ffffffff8318c92c RDX: ffff888036ccde00 RSI: ffffffff8318c2f1
    RDI: 0000000000000001 RBP: ffff88805a2dd6e0 R08: 0000000000000001 R09: 0000000000000000 R10:
    0000000000000000 R11: 0001ffffffffffff R12: ffff88805a2dd680 R13: 0000000000000007 R14: ffff88800923f900
    R15: ffff88805456004e FS: 00007fc449127640(0000) GS:ffff88807dc00000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fc449126e38 CR3: 000000003de4b002 CR4: 0000000000770ef0
    DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6:
    00000000fffe0ff0 DR7: 0000000000000600 PKRU: 55555554 Call Trace: <TASK>
    ip_rcv_finish_core.constprop.0+0xbdd/0xd20 net/ipv4/ip_input.c:349 ip_rcv_finish+0xda/0x150
    net/ipv4/ip_input.c:447 NF_HOOK include/linux/netfilter.h:314 [inline] NF_HOOK
    include/linux/netfilter.h:308 [inline] ip_rcv+0x16c/0x180 net/ipv4/ip_input.c:569
    __netif_receive_skb_one_core+0xb3/0xe0 net/core/dev.c:5624 __netif_receive_skb+0x21/0xd0
    net/core/dev.c:5738 netif_receive_skb_internal net/core/dev.c:5824 [inline] netif_receive_skb+0x271/0x300
    net/core/dev.c:5884 tun_rx_batched drivers/net/tun.c:1549 [inline] tun_get_user+0x24db/0x2c50
    drivers/net/tun.c:2002 tun_chr_write_iter+0x107/0x1a0 drivers/net/tun.c:2048 new_sync_write
    fs/read_write.c:497 [inline] vfs_write+0x76f/0x8d0 fs/read_write.c:590 ksys_write+0xbf/0x190
    fs/read_write.c:643 __do_sys_write fs/read_write.c:655 [inline] __se_sys_write fs/read_write.c:652
    [inline] __x64_sys_write+0x41/0x50 fs/read_write.c:652 x64_sys_call+0xe66/0x1990
    arch/x86/include/generated/asm/syscalls_64.h:2 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0x4b/0x110 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x4b/0x53 RIP:
    0033:0x7fc44a68bc1f Code: 89 54 24 18 48 89 74 24 10 89 7c 24 08 e8 e9 cf f5 ff 48 8b 54 24 18 48 8b 74 24
    10 41 89 c0 8b 7c 24 08 b8 01 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 31 44 89 c7 48 89 44 24 08 e8 3c d0 f5
    ff 48 RSP: 002b:00007fc449126c90 EFLAGS: 00000293 ORIG_RAX: 0000000000000001 RAX: ffffffffffffffda RBX:
    00000000004bc050 RCX: 00007fc44a68bc1f R ---truncated--- (CVE-2024-41041)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41041");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
