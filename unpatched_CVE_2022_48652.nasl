#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225321);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48652");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48652");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ice: Fix crash by keep old cfg when
    update TCs more than queues There are problems if allocated queues less than Traffic Classes. Commit
    a632b2a4c920 (ice: ethtool: Prohibit improper channel config for DCB) already disallow setting less
    queues than TCs. Another case is if we first set less queues, and later update more TCs config due to
    LLDP, ice_vsi_cfg_tc() will failed but left dirty num_txq/rxq and tc_cfg in vsi, that will cause invalid
    pointer access. [ 95.968089] ice 0000:3b:00.1: More TCs defined than queues/rings allocated. [ 95.968092]
    ice 0000:3b:00.1: Trying to use more Rx queues (8), than were allocated (1)! [ 95.968093] ice
    0000:3b:00.1: Failed to config TC for VSI index: 0 [ 95.969621] general protection fault: 0000 [#1] SMP
    NOPTI [ 95.969705] CPU: 1 PID: 58405 Comm: lldpad Kdump: loaded Tainted: G U W O --------- -t - 4.18.0 #1
    [ 95.969867] Hardware name: O.E.M/BC11SPSCB10, BIOS 8.23 12/30/2021 [ 95.969992] RIP:
    0010:devm_kmalloc+0xa/0x60 [ 95.970052] Code: 5c ff ff ff 31 c0 5b 5d 41 5c c3 b8 f4 ff ff ff eb f4 0f 1f
    40 00 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 44 00 00 48 89 f8 89 d1 <8b> 97 60 02 00 00 48 8d 7e 18 48 39 f7
    72 3f 55 89 ce 53 48 8b 4c [ 95.970344] RSP: 0018:ffffc9003f553888 EFLAGS: 00010206 [ 95.970425] RAX:
    dead000000000200 RBX: ffffea003c425b00 RCX: 00000000006080c0 [ 95.970536] RDX: 00000000006080c0 RSI:
    0000000000000200 RDI: dead000000000200 [ 95.970648] RBP: dead000000000200 R08: 00000000000463c0 R09:
    ffff888ffa900000 [ 95.970760] R10: 0000000000000000 R11: 0000000000000002 R12: ffff888ff6b40100 [
    95.970870] R13: ffff888ff6a55018 R14: 0000000000000000 R15: ffff888ff6a55460 [ 95.970981] FS:
    00007f51b7d24700(0000) GS:ffff88903ee80000(0000) knlGS:0000000000000000 [ 95.971108] CS: 0010 DS: 0000 ES:
    0000 CR0: 0000000080050033 [ 95.971197] CR2: 00007fac5410d710 CR3: 0000000f2c1de002 CR4: 00000000007606e0
    [ 95.971309] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [ 95.971419] DR3:
    0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [ 95.971530] PKRU: 55555554 [ 95.971573] Call
    Trace: [ 95.971622] ice_setup_rx_ring+0x39/0x110 [ice] [ 95.971695] ice_vsi_setup_rx_rings+0x54/0x90 [ice]
    [ 95.971774] ice_vsi_open+0x25/0x120 [ice] [ 95.971843] ice_open_internal+0xb8/0x1f0 [ice] [ 95.971919]
    ice_ena_vsi+0x4f/0xd0 [ice] [ 95.971987] ice_dcb_ena_dis_vsi.constprop.5+0x29/0x90 [ice] [ 95.972082]
    ice_pf_dcb_cfg+0x29a/0x380 [ice] [ 95.972154] ice_dcbnl_setets+0x174/0x1b0 [ice] [ 95.972220]
    dcbnl_ieee_set+0x89/0x230 [ 95.972279] ? dcbnl_ieee_del+0x150/0x150 [ 95.972341] dcb_doit+0x124/0x1b0 [
    95.972392] rtnetlink_rcv_msg+0x243/0x2f0 [ 95.972457] ? dcb_doit+0x14d/0x1b0 [ 95.972510] ?
    __kmalloc_node_track_caller+0x1d3/0x280 [ 95.972591] ? rtnl_calcit.isra.31+0x100/0x100 [ 95.972661]
    netlink_rcv_skb+0xcf/0xf0 [ 95.972720] netlink_unicast+0x16d/0x220 [ 95.972781]
    netlink_sendmsg+0x2ba/0x3a0 [ 95.975891] sock_sendmsg+0x4c/0x50 [ 95.979032] ___sys_sendmsg+0x2e4/0x300 [
    95.982147] ? kmem_cache_alloc+0x13e/0x190 [ 95.985242] ? __wake_up_common_lock+0x79/0x90 [ 95.988338] ?
    __check_object_size+0xac/0x1b0 [ 95.991440] ? _copy_to_user+0x22/0x30 [ 95.994539] ?
    move_addr_to_user+0xbb/0xd0 [ 95.997619] ? __sys_sendmsg+0x53/0x80 [ 96.000664] __sys_sendmsg+0x53/0x80 [
    96.003747] do_syscall_64+0x5b/0x1d0 [ 96.006862] entry_SYSCALL_64_after_hwframe+0x65/0xca Only update
    num_txq/rxq when passed check, and restore tc_cfg if setup queue map failed. (CVE-2022-48652)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48652");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/28");
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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
