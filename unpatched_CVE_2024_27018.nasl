#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227710);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-27018");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-27018");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: br_netfilter: skip
    conntrack input hook for promisc packets For historical reasons, when bridge device is in promisc mode,
    packets that are directed to the taps follow bridge input hook path. This patch adds a workaround to reset
    conntrack for these packets. Jianbo Liu reports warning splats in their test infrastructure where cloned
    packets reach the br_netfilter input hook to confirm the conntrack object. Scratch one bit from
    BR_INPUT_SKB_CB to annotate that this packet has reached the input hook because it is passed up to the
    bridge device to reach the taps. [ 57.571874] WARNING: CPU: 1 PID: 0 at
    net/bridge/br_netfilter_hooks.c:616 br_nf_local_in+0x157/0x180 [br_netfilter] [ 57.572749] Modules linked
    in: xt_MASQUERADE nf_conntrack_netlink nfnetlink iptable_nat xt_addrtype xt_conntrack nf_nat br_netfilter
    rpcsec_gss_krb5 auth_rpcgss oid_registry overlay rpcrdma rdma_ucm ib_iser libiscsi scsi_transport_isc si
    ib_umad rdma_cm ib_ipoib iw_cm ib_cm mlx5_ib ib_uverbs ib_core mlx5ctl mlx5_core [ 57.575158] CPU: 1 PID:
    0 Comm: swapper/1 Not tainted 6.8.0+ #19 [ 57.575700] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
    BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 [ 57.576662] RIP:
    0010:br_nf_local_in+0x157/0x180 [br_netfilter] [ 57.577195] Code: fe ff ff 41 bd 04 00 00 00 be 04 00 00
    00 e9 4a ff ff ff be 04 00 00 00 48 89 ef e8 f3 a9 3c e1 66 83 ad b4 00 00 00 04 eb 91 <0f> 0b e9 f1 fe ff
    ff 0f 0b e9 df fe ff ff 48 89 df e8 b3 53 47 e1 [ 57.578722] RSP: 0018:ffff88885f845a08 EFLAGS: 00010202 [
    57.579207] RAX: 0000000000000002 RBX: ffff88812dfe8000 RCX: 0000000000000000 [ 57.579830] RDX:
    ffff88885f845a60 RSI: ffff8881022dc300 RDI: 0000000000000000 [ 57.580454] RBP: ffff88885f845a60 R08:
    0000000000000001 R09: 0000000000000003 [ 57.581076] R10: 00000000ffff1300 R11: 0000000000000002 R12:
    0000000000000000 [ 57.581695] R13: ffff8881047ffe00 R14: ffff888108dbee00 R15: ffff88814519b800 [
    57.582313] FS: 0000000000000000(0000) GS:ffff88885f840000(0000) knlGS:0000000000000000 [ 57.583040] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 57.583564] CR2: 000000c4206aa000 CR3: 0000000103847001 CR4:
    0000000000370eb0 [ 57.584194] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [
    57.584820] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [ 57.585440] Call Trace: [
    57.585721] <IRQ> [ 57.585976] ? __warn+0x7d/0x130 [ 57.586323] ? br_nf_local_in+0x157/0x180 [br_netfilter]
    [ 57.586811] ? report_bug+0xf1/0x1c0 [ 57.587177] ? handle_bug+0x3f/0x70 [ 57.587539] ?
    exc_invalid_op+0x13/0x60 [ 57.587929] ? asm_exc_invalid_op+0x16/0x20 [ 57.588336] ?
    br_nf_local_in+0x157/0x180 [br_netfilter] [ 57.588825] nf_hook_slow+0x3d/0xd0 [ 57.589188] ?
    br_handle_vlan+0x4b/0x110 [ 57.589579] br_pass_frame_up+0xfc/0x150 [ 57.589970] ?
    br_port_flags_change+0x40/0x40 [ 57.590396] br_handle_frame_finish+0x346/0x5e0 [ 57.590837] ?
    ipt_do_table+0x32e/0x430 [ 57.591221] ? br_handle_local_finish+0x20/0x20 [ 57.591656]
    br_nf_hook_thresh+0x4b/0xf0 [br_netfilter] [ 57.592286] ? br_handle_local_finish+0x20/0x20 [ 57.592802]
    br_nf_pre_routing_finish+0x178/0x480 [br_netfilter] [ 57.593348] ? br_handle_local_finish+0x20/0x20 [
    57.593782] ? nf_nat_ipv4_pre_routing+0x25/0x60 [nf_nat] [ 57.594279] br_nf_pre_routing+0x24c/0x550
    [br_netfilter] [ 57.594780] ? br_nf_hook_thresh+0xf0/0xf0 [br_netfilter] [ 57.595280]
    br_handle_frame+0x1f3/0x3d0 [ 57.595676] ? br_handle_local_finish+0x20/0x20 [ 57.596118] ?
    br_handle_frame_finish+0x5e0/0x5e0 [ 57.596566] __netif_receive_skb_core+0x25b/0xfc0 [ 57.597017] ?
    __napi_build_skb+0x37/0x40 [ 57.597418] __netif_receive_skb_list_core+0xfb/0x220 (CVE-2024-27018)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-azure-fips",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "22.04"
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
