#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228584);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40959");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40959");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: xfrm6: check ip6_dst_idev() return
    value in xfrm6_get_saddr() ip6_dst_idev() can return NULL, xfrm6_get_saddr() must act accordingly. syzbot
    reported: Oops: general protection fault, probably for non-canonical address 0xdffffc0000000000: 0000 [#1]
    PREEMPT SMP KASAN PTI KASAN: null-ptr-deref in range [0x0000000000000000-0x0000000000000007] CPU: 1 PID:
    12 Comm: kworker/u8:1 Not tainted 6.10.0-rc2-syzkaller-00383-gb8481381d4e2 #0 Hardware name: Google Google
    Compute Engine/Google Compute Engine, BIOS Google 04/02/2024 Workqueue: wg-kex-wg1
    wg_packet_handshake_send_worker RIP: 0010:xfrm6_get_saddr+0x93/0x130 net/ipv6/xfrm6_policy.c:64 Code: df
    48 89 fa 48 c1 ea 03 80 3c 02 00 0f 85 97 00 00 00 4c 8b ab d8 00 00 00 48 b8 00 00 00 00 00 fc ff df 4c
    89 ea 48 c1 ea 03 <80> 3c 02 00 0f 85 86 00 00 00 4d 8b 6d 00 e8 ca 13 47 01 48 b8 00 RSP:
    0018:ffffc90000117378 EFLAGS: 00010246 RAX: dffffc0000000000 RBX: ffff88807b079dc0 RCX: ffffffff89a0d6d7
    RDX: 0000000000000000 RSI: ffffffff89a0d6e9 RDI: ffff88807b079e98 RBP: ffff88807ad73248 R08:
    0000000000000007 R09: fffffffffffff000 R10: ffff88807b079dc0 R11: 0000000000000007 R12: ffffc90000117480
    R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000 FS: 0000000000000000(0000)
    GS:ffff8880b9300000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007f4586d00440 CR3: 0000000079042000 CR4: 00000000003506f0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK>
    xfrm_get_saddr net/xfrm/xfrm_policy.c:2452 [inline] xfrm_tmpl_resolve_one net/xfrm/xfrm_policy.c:2481
    [inline] xfrm_tmpl_resolve+0xa26/0xf10 net/xfrm/xfrm_policy.c:2541
    xfrm_resolve_and_create_bundle+0x140/0x2570 net/xfrm/xfrm_policy.c:2835 xfrm_bundle_lookup
    net/xfrm/xfrm_policy.c:3070 [inline] xfrm_lookup_with_ifid+0x4d1/0x1e60 net/xfrm/xfrm_policy.c:3201
    xfrm_lookup net/xfrm/xfrm_policy.c:3298 [inline] xfrm_lookup_route+0x3b/0x200 net/xfrm/xfrm_policy.c:3309
    ip6_dst_lookup_flow+0x15c/0x1d0 net/ipv6/ip6_output.c:1256 send6+0x611/0xd20
    drivers/net/wireguard/socket.c:139 wg_socket_send_skb_to_peer+0xf9/0x220
    drivers/net/wireguard/socket.c:178 wg_socket_send_buffer_to_peer+0x12b/0x190
    drivers/net/wireguard/socket.c:200 wg_packet_send_handshake_initiation+0x227/0x360
    drivers/net/wireguard/send.c:40 wg_packet_handshake_send_worker+0x1c/0x30 drivers/net/wireguard/send.c:51
    process_one_work+0x9fb/0x1b60 kernel/workqueue.c:3231 process_scheduled_works kernel/workqueue.c:3312
    [inline] worker_thread+0x6c8/0xf70 kernel/workqueue.c:3393 kthread+0x2c1/0x3a0 kernel/kthread.c:389
    ret_from_fork+0x45/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30
    arch/x86/entry/entry_64.S:244 (CVE-2024-40959)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40959");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/12");
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
