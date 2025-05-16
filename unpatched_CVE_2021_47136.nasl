#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229822);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47136");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47136");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: zero-initialize tc skb extension
    on allocation Function skb_ext_add() doesn't initialize created skb extension with any value and leaves it
    up to the user. However, since extension of type TC_SKB_EXT originally contained only single value
    tc_skb_ext->chain its users used to just assign the chain value without setting whole extension memory to
    zero first. This assumption changed when TC_SKB_EXT extension was extended with additional fields but not
    all users were updated to initialize the new fields which leads to use of uninitialized memory afterwards.
    UBSAN log: [ 778.299821] UBSAN: invalid-load in net/openvswitch/flow.c:899:28 [ 778.301495] load of value
    107 is not a valid value for type '_Bool' [ 778.303215] CPU: 0 PID: 0 Comm: swapper/0 Not tainted
    5.12.0-rc7+ #2 [ 778.304933] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
    rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 [ 778.307901] Call Trace: [ 778.308680] <IRQ> [
    778.309358] dump_stack+0xbb/0x107 [ 778.310307] ubsan_epilogue+0x5/0x40 [ 778.311167]
    __ubsan_handle_load_invalid_value.cold+0x43/0x48 [ 778.312454] ? memset+0x20/0x40 [ 778.313230]
    ovs_flow_key_extract.cold+0xf/0x14 [openvswitch] [ 778.314532] ovs_vport_receive+0x19e/0x2e0 [openvswitch]
    [ 778.315749] ? ovs_vport_find_upcall_portid+0x330/0x330 [openvswitch] [ 778.317188] ?
    create_prof_cpu_mask+0x20/0x20 [ 778.318220] ? arch_stack_walk+0x82/0xf0 [ 778.319153] ?
    secondary_startup_64_no_verify+0xb0/0xbb [ 778.320399] ? stack_trace_save+0x91/0xc0 [ 778.321362] ?
    stack_trace_consume_entry+0x160/0x160 [ 778.322517] ? lock_release+0x52e/0x760 [ 778.323444]
    netdev_frame_hook+0x323/0x610 [openvswitch] [ 778.324668] ? ovs_netdev_get_vport+0xe0/0xe0 [openvswitch] [
    778.325950] __netif_receive_skb_core+0x771/0x2db0 [ 778.327067] ? lock_downgrade+0x6e0/0x6f0 [ 778.328021]
    ? lock_acquire+0x565/0x720 [ 778.328940] ? generic_xdp_tx+0x4f0/0x4f0 [ 778.329902] ?
    inet_gro_receive+0x2a7/0x10a0 [ 778.330914] ? lock_downgrade+0x6f0/0x6f0 [ 778.331867] ?
    udp4_gro_receive+0x4c4/0x13e0 [ 778.332876] ? lock_release+0x52e/0x760 [ 778.333808] ?
    dev_gro_receive+0xcc8/0x2380 [ 778.334810] ? lock_downgrade+0x6f0/0x6f0 [ 778.335769]
    __netif_receive_skb_list_core+0x295/0x820 [ 778.336955] ? process_backlog+0x780/0x780 [ 778.337941] ?
    mlx5e_rep_tc_netdevice_event_unregister+0x20/0x20 [mlx5_core] [ 778.339613] ?
    seqcount_lockdep_reader_access.constprop.0+0xa7/0xc0 [ 778.341033] ? kvm_clock_get_cycles+0x14/0x20 [
    778.342072] netif_receive_skb_list_internal+0x5f5/0xcb0 [ 778.343288] ? __kasan_kmalloc+0x7a/0x90 [
    778.344234] ? mlx5e_handle_rx_cqe_mpwrq+0x9e0/0x9e0 [mlx5_core] [ 778.345676] ?
    mlx5e_xmit_xdp_frame_mpwqe+0x14d0/0x14d0 [mlx5_core] [ 778.347140] ?
    __netif_receive_skb_list_core+0x820/0x820 [ 778.348351] ? mlx5e_post_rx_mpwqes+0xa6/0x25d0 [mlx5_core] [
    778.349688] ? napi_gro_flush+0x26c/0x3c0 [ 778.350641] napi_complete_done+0x188/0x6b0 [ 778.351627]
    mlx5e_napi_poll+0x373/0x1b80 [mlx5_core] [ 778.352853] __napi_poll+0x9f/0x510 [ 778.353704] ?
    mlx5_flow_namespace_set_mode+0x260/0x260 [mlx5_core] [ 778.355158] net_rx_action+0x34c/0xa40 [ 778.356060]
    ? napi_threaded_poll+0x3d0/0x3d0 [ 778.357083] ? sched_clock_cpu+0x18/0x190 [ 778.358041] ?
    __common_interrupt+0x8e/0x1a0 [ 778.359045] __do_softirq+0x1ce/0x984 [ 778.359938]
    __irq_exit_rcu+0x137/0x1d0 [ 778.360865] irq_exit_rcu+0xa/0x20 [ 778.361708] common_interrupt+0x80/0xa0 [
    778.362640] </IRQ> [ 778.363212] asm_common_interrupt+0x1e/0x40 [ 778.364204] RIP:
    0010:native_safe_halt+0xe/0x10 [ 778.365273] Code: 4f ff ff ff 4c 89 e7 e8 50 3f 40 fe e9 dc fe ff ff 48
    89 df e8 43 3f 40 fe eb 90 cc e9 07 00 00 00 0f 00 2d 74 05 62 00 fb f4 <c3> 90 e9 07 00 00 00 0f 00 2d 64
    05 62 00 f4 c3 cc cc 0f 1f 44 00 [ 778.369355] RSP: 0018:ffffffff84407e48 EFLAGS: 00000246 [ 778.370570]
    RAX ---truncated--- (CVE-2021-47136)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47136");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
