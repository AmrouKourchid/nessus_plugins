#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230206);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47594");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47594");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mptcp: never allow the PM to close a
    listener subflow Currently, when deleting an endpoint the netlink PM treverses all the local MPTCP
    sockets, regardless of their status. If an MPTCP listener socket is bound to the IP matching the delete
    endpoint, the listener TCP socket will be closed. That is unexpected, the PM should only affect data
    subflows. Additionally, syzbot was able to trigger a NULL ptr dereference due to the above: general
    protection fault, probably for non-canonical address 0xdffffc0000000003: 0000 [#1] PREEMPT SMP KASAN
    KASAN: null-ptr-deref in range [0x0000000000000018-0x000000000000001f] CPU: 1 PID: 6550 Comm: syz-
    executor122 Not tainted 5.16.0-rc4-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute
    Engine, BIOS Google 01/01/2011 RIP: 0010:__lock_acquire+0xd7d/0x54a0 kernel/locking/lockdep.c:4897 Code:
    0f 0e 41 be 01 00 00 00 0f 86 c8 00 00 00 89 05 69 cc 0f 0e e9 bd 00 00 00 48 b8 00 00 00 00 00 fc ff df
    48 89 da 48 c1 ea 03 <80> 3c 02 00 0f 85 f3 2f 00 00 48 81 3b 20 75 17 8f 0f 84 52 f3 ff RSP:
    0018:ffffc90001f2f818 EFLAGS: 00010016 RAX: dffffc0000000000 RBX: 0000000000000018 RCX: 0000000000000000
    RDX: 0000000000000003 RSI: 0000000000000000 RDI: 0000000000000001 RBP: 0000000000000000 R08:
    0000000000000001 R09: 0000000000000001 R10: 0000000000000000 R11: 000000000000000a R12: 0000000000000000
    R13: ffff88801b98d700 R14: 0000000000000000 R15: 0000000000000001 FS: 00007f177cd3d700(0000)
    GS:ffff8880b9d00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007f177cd1b268 CR3: 000000001dd55000 CR4: 0000000000350ee0 Call Trace: <TASK> lock_acquire
    kernel/locking/lockdep.c:5637 [inline] lock_acquire+0x1ab/0x510 kernel/locking/lockdep.c:5602
    __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline] _raw_spin_lock_irqsave+0x39/0x50
    kernel/locking/spinlock.c:162 finish_wait+0xc0/0x270 kernel/sched/wait.c:400 inet_csk_wait_for_connect
    net/ipv4/inet_connection_sock.c:464 [inline] inet_csk_accept+0x7de/0x9d0
    net/ipv4/inet_connection_sock.c:497 mptcp_accept+0xe5/0x500 net/mptcp/protocol.c:2865
    inet_accept+0xe4/0x7b0 net/ipv4/af_inet.c:739 mptcp_stream_accept+0x2e7/0x10e0 net/mptcp/protocol.c:3345
    do_accept+0x382/0x510 net/socket.c:1773 __sys_accept4_file+0x7e/0xe0 net/socket.c:1816
    __sys_accept4+0xb0/0x100 net/socket.c:1846 __do_sys_accept net/socket.c:1864 [inline] __se_sys_accept
    net/socket.c:1861 [inline] __x64_sys_accept+0x71/0xb0 net/socket.c:1861 do_syscall_x64
    arch/x86/entry/common.c:50 [inline] do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x44/0xae RIP: 0033:0x7f177cd8b8e9 Code: 28 00 00 00 75 05 48 83 c4 28 c3
    e8 b1 14 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0
    ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007f177cd3d308 EFLAGS: 00000246
    ORIG_RAX: 000000000000002b RAX: ffffffffffffffda RBX: 00007f177ce13408 RCX: 00007f177cd8b8e9 RDX:
    0000000000000000 RSI: 0000000000000000 RDI: 0000000000000003 RBP: 00007f177ce13400 R08: 0000000000000000
    R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 00007f177ce1340c R13:
    00007f177cde1004 R14: 6d705f706374706d R15: 0000000000022000 </TASK> Fix the issue explicitly skipping
    MPTCP socket in TCP_LISTEN status. (CVE-2021-47594)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47594");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/19");
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
