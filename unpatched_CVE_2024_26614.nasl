#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228111);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26614");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26614");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tcp: make sure init the accept_queue's
    spinlocks once When I run syz's reproduction C program locally, it causes the following issue:
    pvqspinlock: lock 0xffff9d181cd5c660 has corrupted value 0x0! WARNING: CPU: 19 PID: 21160 at
    __pv_queued_spin_unlock_slowpath (kernel/locking/qspinlock_paravirt.h:508) Hardware name: Red Hat KVM,
    BIOS 0.5.1 01/01/2011 RIP: 0010:__pv_queued_spin_unlock_slowpath (kernel/locking/qspinlock_paravirt.h:508)
    Code: 73 56 3a ff 90 c3 cc cc cc cc 8b 05 bb 1f 48 01 85 c0 74 05 c3 cc cc cc cc 8b 17 48 89 fe 48 c7 c7
    30 20 ce 8f e8 ad 56 42 ff <0f> 0b c3 cc cc cc cc 0f 0b 0f 1f 40 00 90 90 90 90 90 90 90 90 90 RSP:
    0018:ffffa8d200604cb8 EFLAGS: 00010282 RAX: 0000000000000000 RBX: 0000000000000000 RCX: ffff9d1ef60e0908
    RDX: 00000000ffffffd8 RSI: 0000000000000027 RDI: ffff9d1ef60e0900 RBP: ffff9d181cd5c280 R08:
    0000000000000000 R09: 00000000ffff7fff R10: ffffa8d200604b68 R11: ffffffff907dcdc8 R12: 0000000000000000
    R13: ffff9d181cd5c660 R14: ffff9d1813a3f330 R15: 0000000000001000 FS: 00007fa110184640(0000)
    GS:ffff9d1ef60c0000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    0000000020000000 CR3: 000000011f65e000 CR4: 00000000000006f0 Call Trace: <IRQ> _raw_spin_unlock
    (kernel/locking/spinlock.c:186) inet_csk_reqsk_queue_add (net/ipv4/inet_connection_sock.c:1321)
    inet_csk_complete_hashdance (net/ipv4/inet_connection_sock.c:1358) tcp_check_req
    (net/ipv4/tcp_minisocks.c:868) tcp_v4_rcv (net/ipv4/tcp_ipv4.c:2260) ip_protocol_deliver_rcu
    (net/ipv4/ip_input.c:205) ip_local_deliver_finish (net/ipv4/ip_input.c:234) __netif_receive_skb_one_core
    (net/core/dev.c:5529) process_backlog (./include/linux/rcupdate.h:779) __napi_poll (net/core/dev.c:6533)
    net_rx_action (net/core/dev.c:6604) __do_softirq (./arch/x86/include/asm/jump_label.h:27) do_softirq
    (kernel/softirq.c:454 kernel/softirq.c:441) </IRQ> <TASK> __local_bh_enable_ip (kernel/softirq.c:381)
    __dev_queue_xmit (net/core/dev.c:4374) ip_finish_output2 (./include/net/neighbour.h:540
    net/ipv4/ip_output.c:235) __ip_queue_xmit (net/ipv4/ip_output.c:535) __tcp_transmit_skb
    (net/ipv4/tcp_output.c:1462) tcp_rcv_synsent_state_process (net/ipv4/tcp_input.c:6469)
    tcp_rcv_state_process (net/ipv4/tcp_input.c:6657) tcp_v4_do_rcv (net/ipv4/tcp_ipv4.c:1929) __release_sock
    (./include/net/sock.h:1121 net/core/sock.c:2968) release_sock (net/core/sock.c:3536) inet_wait_for_connect
    (net/ipv4/af_inet.c:609) __inet_stream_connect (net/ipv4/af_inet.c:702) inet_stream_connect
    (net/ipv4/af_inet.c:748) __sys_connect (./include/linux/file.h:45 net/socket.c:2064) __x64_sys_connect
    (net/socket.c:2073 net/socket.c:2070 net/socket.c:2070) do_syscall_64 (arch/x86/entry/common.c:51
    arch/x86/entry/common.c:82) entry_SYSCALL_64_after_hwframe (arch/x86/entry/entry_64.S:129) RIP:
    0033:0x7fa10ff05a3d Code: 5b 41 5c c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48
    89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d ab a3 0e 00 f7 d8 64 89
    01 48 RSP: 002b:00007fa110183de8 EFLAGS: 00000202 ORIG_RAX: 000000000000002a RAX: ffffffffffffffda RBX:
    0000000020000054 RCX: 00007fa10ff05a3d RDX: 000000000000001c RSI: 0000000020000040 RDI: 0000000000000003
    RBP: 00007fa110183e20 R08: 0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11:
    0000000000000202 R12: 00007fa110184640 R13: 0000000000000000 R14: 00007fa10fe8b060 R15: 00007fff73e23b20
    </TASK> The issue triggering process is analyzed as follows: Thread A Thread B tcp_v4_rcv //receive ack
    TCP packet inet_shutdown tcp_check_req tcp_disconnect //disconnect sock ... tcp_set_state(sk, TCP_CLOSE)
    inet_csk_complete_hashdance ... inet_csk_reqsk_queue_add ---truncated--- (CVE-2024-26614)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26614");

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
