#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226799);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52637");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52637");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: can: j1939: Fix UAF in
    j1939_sk_match_filter during setsockopt(SO_J1939_FILTER) Lock jsk->sk to prevent UAF when setsockopt(...,
    SO_J1939_FILTER, ...) modifies jsk->filters while receiving packets. Following trace was seen on affected
    system: ================================================================== BUG: KASAN: slab-use-after-free
    in j1939_sk_recv_match_one+0x1af/0x2d0 [can_j1939] Read of size 4 at addr ffff888012144014 by task
    j1939/350 CPU: 0 PID: 350 Comm: j1939 Tainted: G W OE 6.5.0-rc5 #1 Hardware name: QEMU Standard PC (i440FX
    + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014 Call Trace: print_report+0xd3/0x620 ?
    kasan_complete_mode_report_info+0x7d/0x200 ? j1939_sk_recv_match_one+0x1af/0x2d0 [can_j1939]
    kasan_report+0xc2/0x100 ? j1939_sk_recv_match_one+0x1af/0x2d0 [can_j1939] __asan_load4+0x84/0xb0
    j1939_sk_recv_match_one+0x1af/0x2d0 [can_j1939] j1939_sk_recv+0x20b/0x320 [can_j1939] ?
    __kasan_check_write+0x18/0x20 ? __pfx_j1939_sk_recv+0x10/0x10 [can_j1939] ? j1939_simple_recv+0x69/0x280
    [can_j1939] ? j1939_ac_recv+0x5e/0x310 [can_j1939] j1939_can_recv+0x43f/0x580 [can_j1939] ?
    __pfx_j1939_can_recv+0x10/0x10 [can_j1939] ? raw_rcv+0x42/0x3c0 [can_raw] ? __pfx_j1939_can_recv+0x10/0x10
    [can_j1939] can_rcv_filter+0x11f/0x350 [can] can_receive+0x12f/0x190 [can] ? __pfx_can_rcv+0x10/0x10 [can]
    can_rcv+0xdd/0x130 [can] ? __pfx_can_rcv+0x10/0x10 [can] __netif_receive_skb_one_core+0x13d/0x150 ?
    __pfx___netif_receive_skb_one_core+0x10/0x10 ? __kasan_check_write+0x18/0x20 ?
    _raw_spin_lock_irq+0x8c/0xe0 __netif_receive_skb+0x23/0xb0 process_backlog+0x107/0x260
    __napi_poll+0x69/0x310 net_rx_action+0x2a1/0x580 ? __pfx_net_rx_action+0x10/0x10 ?
    __pfx__raw_spin_lock+0x10/0x10 ? handle_irq_event+0x7d/0xa0 __do_softirq+0xf3/0x3f8 do_softirq+0x53/0x80
    </IRQ> <TASK> __local_bh_enable_ip+0x6e/0x70 netif_rx+0x16b/0x180 can_send+0x32b/0x520 [can] ?
    __pfx_can_send+0x10/0x10 [can] ? __check_object_size+0x299/0x410 raw_sendmsg+0x572/0x6d0 [can_raw] ?
    __pfx_raw_sendmsg+0x10/0x10 [can_raw] ? apparmor_socket_sendmsg+0x2f/0x40 ? __pfx_raw_sendmsg+0x10/0x10
    [can_raw] sock_sendmsg+0xef/0x100 sock_write_iter+0x162/0x220 ? __pfx_sock_write_iter+0x10/0x10 ?
    __rtnl_unlock+0x47/0x80 ? security_file_permission+0x54/0x320 vfs_write+0x6ba/0x750 ?
    __pfx_vfs_write+0x10/0x10 ? __fget_light+0x1ca/0x1f0 ? __rcu_read_unlock+0x5b/0x280 ksys_write+0x143/0x170
    ? __pfx_ksys_write+0x10/0x10 ? __kasan_check_read+0x15/0x20 ? fpregs_assert_state_consistent+0x62/0x70
    __x64_sys_write+0x47/0x60 do_syscall_64+0x60/0x90 ? do_syscall_64+0x6d/0x90 ? irqentry_exit+0x3f/0x50 ?
    exc_page_fault+0x79/0xf0 entry_SYSCALL_64_after_hwframe+0x6e/0xd8 Allocated by task 348:
    kasan_save_stack+0x2a/0x50 kasan_set_track+0x29/0x40 kasan_save_alloc_info+0x1f/0x30
    __kasan_kmalloc+0xb5/0xc0 __kmalloc_node_track_caller+0x67/0x160 j1939_sk_setsockopt+0x284/0x450
    [can_j1939] __sys_setsockopt+0x15c/0x2f0 __x64_sys_setsockopt+0x6b/0x80 do_syscall_64+0x60/0x90
    entry_SYSCALL_64_after_hwframe+0x6e/0xd8 Freed by task 349: kasan_save_stack+0x2a/0x50
    kasan_set_track+0x29/0x40 kasan_save_free_info+0x2f/0x50 __kasan_slab_free+0x12e/0x1c0
    __kmem_cache_free+0x1b9/0x380 kfree+0x7a/0x120 j1939_sk_setsockopt+0x3b2/0x450 [can_j1939]
    __sys_setsockopt+0x15c/0x2f0 __x64_sys_setsockopt+0x6b/0x80 do_syscall_64+0x60/0x90
    entry_SYSCALL_64_after_hwframe+0x6e/0xd8 (CVE-2023-52637)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52637");

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
