#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226795);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52487");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52487");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: Fix peer flow lists
    handling The cited change refactored mlx5e_tc_del_fdb_peer_flow() to only clear DUP flag when list of peer
    flows has become empty. However, if any concurrent user holds a reference to a peer flow (for example, the
    neighbor update workqueue task is updating peer flow's parent encap entry concurrently), then the flow
    will not be removed from the peer list and, consecutively, DUP flag will remain set. Since
    mlx5e_tc_del_fdb_peers_flow() calls mlx5e_tc_del_fdb_peer_flow() for every possible peer index the
    algorithm will try to remove the flow from eswitch instances that it has never peered with causing either
    NULL pointer dereference when trying to remove the flow peer list head of peer_index that was never
    initialized or a warning if the list debug config is enabled[0]. Fix the issue by always removing the peer
    flow from the list even when not releasing the last reference to it. [0]: [ 3102.985806] ------------[ cut
    here ]------------ [ 3102.986223] list_del corruption, ffff888139110698->next is NULL [ 3102.986757]
    WARNING: CPU: 2 PID: 22109 at lib/list_debug.c:53 __list_del_entry_valid_or_report+0x4f/0xc0 [
    3102.987561] Modules linked in: act_ct nf_flow_table bonding act_tunnel_key act_mirred act_skbedit vxlan
    cls_matchall nfnetlink_cttimeout act_gact cls_flower sch_ingress mlx5_vdpa vringh vhost_iotlb vdpa
    openvswitch nsh xt_MASQUERADE nf_conntrack_netlink nfnetlink iptable_nat xt_addrtype xt_conntrack nf_nat
    br_netfilter rpcsec_gss_krb5 auth_rpcg ss oid_registry overlay rpcrdma rdma_ucm ib_iser libiscsi
    scsi_transport_iscsi ib_umad rdma_cm ib_ipoib iw_cm ib_cm mlx5_ib ib_uverbs ib_core mlx5_core [last
    unloaded: bonding] [ 3102.991113] CPU: 2 PID: 22109 Comm: revalidator28 Not tainted 6.6.0-rc6+ #3 [
    3102.991695] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
    rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 [ 3102.992605] RIP:
    0010:__list_del_entry_valid_or_report+0x4f/0xc0 [ 3102.993122] Code: 39 c2 74 56 48 8b 32 48 39 fe 75 62
    48 8b 51 08 48 39 f2 75 73 b8 01 00 00 00 c3 48 89 fe 48 c7 c7 48 fd 0a 82 e8 41 0b ad ff <0f> 0b 31 c0 c3
    48 89 fe 48 c7 c7 70 fd 0a 82 e8 2d 0b ad ff 0f 0b [ 3102.994615] RSP: 0018:ffff8881383e7710 EFLAGS:
    00010286 [ 3102.995078] RAX: 0000000000000000 RBX: 0000000000000002 RCX: 0000000000000000 [ 3102.995670]
    RDX: 0000000000000001 RSI: ffff88885f89b640 RDI: ffff88885f89b640 [ 3102.997188] DEL flow 00000000be367878
    on port 0 [ 3102.998594] RBP: dead000000000122 R08: 0000000000000000 R09: c0000000ffffdfff [ 3102.999604]
    R10: 0000000000000008 R11: ffff8881383e7598 R12: dead000000000100 [ 3103.000198] R13: 0000000000000002
    R14: ffff888139110000 R15: ffff888101901240 [ 3103.000790] FS: 00007f424cde4700(0000)
    GS:ffff88885f880000(0000) knlGS:0000000000000000 [ 3103.001486] CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 [ 3103.001986] CR2: 00007fd42e8dcb70 CR3: 000000011e68a003 CR4: 0000000000370ea0 [
    3103.002596] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [ 3103.003190] DR3:
    0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [ 3103.003787] Call Trace: [ 3103.004055]
    <TASK> [ 3103.004297] ? __warn+0x7d/0x130 [ 3103.004623] ? __list_del_entry_valid_or_report+0x4f/0xc0 [
    3103.005094] ? report_bug+0xf1/0x1c0 [ 3103.005439] ? console_unlock+0x4a/0xd0 [ 3103.005806] ?
    handle_bug+0x3f/0x70 [ 3103.006149] ? exc_invalid_op+0x13/0x60 [ 3103.006531] ?
    asm_exc_invalid_op+0x16/0x20 [ 3103.007430] ? __list_del_entry_valid_or_report+0x4f/0xc0 [ 3103.007910]
    mlx5e_tc_del_fdb_peers_flow+0xcf/0x240 [mlx5_core] [ 3103.008463] mlx5e_tc_del_flow+0x46/0x270 [mlx5_core]
    [ 3103.008944] mlx5e_flow_put+0x26/0x50 [mlx5_core] [ 3103.009401] mlx5e_delete_flower+0x25f/0x380
    [mlx5_core] [ 3103.009901] tc_setup_cb_destroy+0xab/0x180 [ 3103.010292] fl_hw_destroy_filter+0x99/0xc0
    [cls_flower] [ 3103.010779] __fl_delete+0x2d4/0x2f0 [cls_flower] [ 3103.0 ---truncated--- (CVE-2023-52487)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52487");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/29");
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
