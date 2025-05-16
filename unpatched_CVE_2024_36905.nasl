#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229095);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36905");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36905");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tcp: defer shutdown(SEND_SHUTDOWN) for
    TCP_SYN_RECV sockets TCP_SYN_RECV state is really special, it is only used by cross-syn connections,
    mostly used by fuzzers. In the following crash [1], syzbot managed to trigger a divide by zero in
    tcp_rcv_space_adjust() A socket makes the following state transitions, without ever calling
    tcp_init_transfer(), meaning tcp_init_buffer_space() is also not called. TCP_CLOSE connect() TCP_SYN_SENT
    TCP_SYN_RECV shutdown() -> tcp_shutdown(sk, SEND_SHUTDOWN) TCP_FIN_WAIT1 To fix this issue, change
    tcp_shutdown() to not perform a TCP_SYN_RECV -> TCP_FIN_WAIT1 transition, which makes no sense anyway.
    When tcp_rcv_state_process() later changes socket state from TCP_SYN_RECV to TCP_ESTABLISH, then look at
    sk->sk_shutdown to finally enter TCP_FIN_WAIT1 state, and send a FIN packet from a sane socket state. This
    means tcp_send_fin() can now be called from BH context, and must use GFP_ATOMIC allocations. [1] divide
    error: 0000 [#1] PREEMPT SMP KASAN NOPTI CPU: 1 PID: 5084 Comm: syz-executor358 Not tainted
    6.9.0-rc6-syzkaller-00022-g98369dccd2f8 #0 Hardware name: Google Google Compute Engine/Google Compute
    Engine, BIOS Google 03/27/2024 RIP: 0010:tcp_rcv_space_adjust+0x2df/0x890 net/ipv4/tcp_input.c:767 Code:
    e3 04 4c 01 eb 48 8b 44 24 38 0f b6 04 10 84 c0 49 89 d5 0f 85 a5 03 00 00 41 8b 8e c8 09 00 00 89 e8 29
    c8 48 0f af c3 31 d2 <48> f7 f1 48 8d 1c 43 49 8d 96 76 08 00 00 48 89 d0 48 c1 e8 03 48 RSP:
    0018:ffffc900031ef3f0 EFLAGS: 00010246 RAX: 0c677a10441f8f42 RBX: 000000004fb95e7e RCX: 0000000000000000
    RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000 RBP: 0000000027d4b11f R08:
    ffffffff89e535a4 R09: 1ffffffff25e6ab7 R10: dffffc0000000000 R11: ffffffff8135e920 R12: ffff88802a9f8d30
    R13: dffffc0000000000 R14: ffff88802a9f8d00 R15: 1ffff1100553f2da FS: 00005555775c0380(0000)
    GS:ffff8880b9500000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007f1155bf2304 CR3: 000000002b9f2000 CR4: 0000000000350ef0 Call Trace: <TASK>
    tcp_recvmsg_locked+0x106d/0x25a0 net/ipv4/tcp.c:2513 tcp_recvmsg+0x25d/0x920 net/ipv4/tcp.c:2578
    inet6_recvmsg+0x16a/0x730 net/ipv6/af_inet6.c:680 sock_recvmsg_nosec net/socket.c:1046 [inline]
    sock_recvmsg+0x109/0x280 net/socket.c:1068 ____sys_recvmsg+0x1db/0x470 net/socket.c:2803 ___sys_recvmsg
    net/socket.c:2845 [inline] do_recvmmsg+0x474/0xae0 net/socket.c:2939 __sys_recvmmsg net/socket.c:3018
    [inline] __do_sys_recvmmsg net/socket.c:3041 [inline] __se_sys_recvmmsg net/socket.c:3034 [inline]
    __x64_sys_recvmmsg+0x199/0x250 net/socket.c:3034 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0xf5/0x240 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP:
    0033:0x7faeb6363db9 Code: 28 00 00 00 75 05 48 83 c4 28 c3 e8 c1 17 00 00 90 48 89 f8 48 89 f7 48 89 d6 48
    89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89
    01 48 RSP: 002b:00007ffcc1997168 EFLAGS: 00000246 ORIG_RAX: 000000000000012b RAX: ffffffffffffffda RBX:
    0000000000000000 RCX: 00007faeb6363db9 RDX: 0000000000000001 RSI: 0000000020000bc0 RDI: 0000000000000005
    RBP: 0000000000000000 R08: 0000000000000000 R09: 000000000000001c R10: 0000000000000122 R11:
    0000000000000246 R12: 0000000000000000 R13: 0000000000000000 R14: 0000000000000001 R15: 0000000000000001
    (CVE-2024-36905)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36905");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/23");
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
