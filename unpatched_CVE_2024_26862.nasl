#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227940);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26862");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26862");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: packet: annotate data-races around
    ignore_outgoing ignore_outgoing is read locklessly from dev_queue_xmit_nit() and packet_getsockopt() Add
    appropriate READ_ONCE()/WRITE_ONCE() annotations. syzbot reported: BUG: KCSAN: data-race in
    dev_queue_xmit_nit / packet_setsockopt write to 0xffff888107804542 of 1 bytes by task 22618 on cpu 0:
    packet_setsockopt+0xd83/0xfd0 net/packet/af_packet.c:4003 do_sock_setsockopt net/socket.c:2311 [inline]
    __sys_setsockopt+0x1d8/0x250 net/socket.c:2334 __do_sys_setsockopt net/socket.c:2343 [inline]
    __se_sys_setsockopt net/socket.c:2340 [inline] __x64_sys_setsockopt+0x66/0x80 net/socket.c:2340
    do_syscall_64+0xd3/0x1d0 entry_SYSCALL_64_after_hwframe+0x6d/0x75 read to 0xffff888107804542 of 1 bytes by
    task 27 on cpu 1: dev_queue_xmit_nit+0x82/0x620 net/core/dev.c:2248 xmit_one net/core/dev.c:3527 [inline]
    dev_hard_start_xmit+0xcc/0x3f0 net/core/dev.c:3547 __dev_queue_xmit+0xf24/0x1dd0 net/core/dev.c:4335
    dev_queue_xmit include/linux/netdevice.h:3091 [inline] batadv_send_skb_packet+0x264/0x300 net/batman-
    adv/send.c:108 batadv_send_broadcast_skb+0x24/0x30 net/batman-adv/send.c:127 batadv_iv_ogm_send_to_if
    net/batman-adv/bat_iv_ogm.c:392 [inline] batadv_iv_ogm_emit net/batman-adv/bat_iv_ogm.c:420 [inline]
    batadv_iv_send_outstanding_bat_ogm_packet+0x3f0/0x4b0 net/batman-adv/bat_iv_ogm.c:1700 process_one_work
    kernel/workqueue.c:3254 [inline] process_scheduled_works+0x465/0x990 kernel/workqueue.c:3335
    worker_thread+0x526/0x730 kernel/workqueue.c:3416 kthread+0x1d1/0x210 kernel/kthread.c:388
    ret_from_fork+0x4b/0x60 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30
    arch/x86/entry/entry_64.S:243 value changed: 0x00 -> 0x01 Reported by Kernel Concurrency Sanitizer on:
    CPU: 1 PID: 27 Comm: kworker/u8:1 Tainted: G W 6.8.0-syzkaller-08073-g480e035fc4c7 #0 Hardware name:
    Google Google Compute Engine/Google Compute Engine, BIOS Google 02/29/2024 Workqueue: bat_events
    batadv_iv_send_outstanding_bat_ogm_packet (CVE-2024-26862)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26862");

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
