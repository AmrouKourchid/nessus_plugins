#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228901);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40923");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40923");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: vmxnet3: disable rx data ring on dma
    allocation failure When vmxnet3_rq_create() fails to allocate memory for rq->data_ring.base, the
    subsequent call to vmxnet3_rq_destroy_all_rxdataring does not reset rq->data_ring.desc_size for the data
    ring that failed, which presumably causes the hypervisor to reference it on packet reception. To fix this
    bug, rq->data_ring.desc_size needs to be set to 0 to tell the hypervisor to disable this feature. [
    95.436876] kernel BUG at net/core/skbuff.c:207! [ 95.439074] invalid opcode: 0000 [#1] PREEMPT SMP NOPTI [
    95.440411] CPU: 7 PID: 0 Comm: swapper/7 Not tainted 6.9.3-dirty #1 [ 95.441558] Hardware name: VMware,
    Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 12/12/2018 [ 95.443481] RIP:
    0010:skb_panic+0x4d/0x4f [ 95.444404] Code: 4f 70 50 8b 87 c0 00 00 00 50 8b 87 bc 00 00 00 50 ff b7 d0 00
    00 00 4c 8b 8f c8 00 00 00 48 c7 c7 68 e8 be 9f e8 63 58 f9 ff <0f> 0b 48 8b 14 24 48 c7 c1 d0 73 65 9f e8
    a1 ff ff ff 48 8b 14 24 [ 95.447684] RSP: 0018:ffffa13340274dd0 EFLAGS: 00010246 [ 95.448762] RAX:
    0000000000000089 RBX: ffff8fbbc72b02d0 RCX: 000000000000083f [ 95.450148] RDX: 0000000000000000 RSI:
    00000000000000f6 RDI: 000000000000083f [ 95.451520] RBP: 000000000000002d R08: 0000000000000000 R09:
    ffffa13340274c60 [ 95.452886] R10: ffffffffa04ed468 R11: 0000000000000002 R12: 0000000000000000 [
    95.454293] R13: ffff8fbbdab3c2d0 R14: ffff8fbbdbd829e0 R15: ffff8fbbdbd809e0 [ 95.455682] FS:
    0000000000000000(0000) GS:ffff8fbeefd80000(0000) knlGS:0000000000000000 [ 95.457178] CS: 0010 DS: 0000 ES:
    0000 CR0: 0000000080050033 [ 95.458340] CR2: 00007fd0d1f650c8 CR3: 0000000115f28000 CR4: 00000000000406f0
    [ 95.459791] Call Trace: [ 95.460515] <IRQ> [ 95.461180] ? __die_body.cold+0x19/0x27 [ 95.462150] ?
    die+0x2e/0x50 [ 95.462976] ? do_trap+0xca/0x110 [ 95.463973] ? do_error_trap+0x6a/0x90 [ 95.464966] ?
    skb_panic+0x4d/0x4f [ 95.465901] ? exc_invalid_op+0x50/0x70 [ 95.466849] ? skb_panic+0x4d/0x4f [
    95.467718] ? asm_exc_invalid_op+0x1a/0x20 [ 95.468758] ? skb_panic+0x4d/0x4f [ 95.469655]
    skb_put.cold+0x10/0x10 [ 95.470573] vmxnet3_rq_rx_complete+0x862/0x11e0 [vmxnet3] [ 95.471853]
    vmxnet3_poll_rx_only+0x36/0xb0 [vmxnet3] [ 95.473185] __napi_poll+0x2b/0x160 [ 95.474145]
    net_rx_action+0x2c6/0x3b0 [ 95.475115] handle_softirqs+0xe7/0x2a0 [ 95.476122] __irq_exit_rcu+0x97/0xb0 [
    95.477109] common_interrupt+0x85/0xa0 [ 95.478102] </IRQ> [ 95.478846] <TASK> [ 95.479603]
    asm_common_interrupt+0x26/0x40 [ 95.480657] RIP: 0010:pv_native_safe_halt+0xf/0x20 [ 95.481801] Code: 22
    d7 e9 54 87 01 00 0f 1f 40 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 0f 1e fa eb 07 0f 00 2d
    93 ba 3b 00 fb f4 <e9> 2c 87 01 00 66 66 2e 0f 1f 84 00 00 00 00 00 90 90 90 90 90 90 [ 95.485563] RSP:
    0018:ffffa133400ffe58 EFLAGS: 00000246 [ 95.486882] RAX: 0000000000004000 RBX: ffff8fbbc1d14064 RCX:
    0000000000000000 [ 95.488477] RDX: ffff8fbeefd80000 RSI: ffff8fbbc1d14000 RDI: 0000000000000001 [
    95.490067] RBP: ffff8fbbc1d14064 R08: ffffffffa0652260 R09: 00000000000010d3 [ 95.491683] R10:
    0000000000000018 R11: ffff8fbeefdb4764 R12: ffffffffa0652260 [ 95.493389] R13: ffffffffa06522e0 R14:
    0000000000000001 R15: 0000000000000000 [ 95.495035] acpi_safe_halt+0x14/0x20 [ 95.496127]
    acpi_idle_do_entry+0x2f/0x50 [ 95.497221] acpi_idle_enter+0x7f/0xd0 [ 95.498272]
    cpuidle_enter_state+0x81/0x420 [ 95.499375] cpuidle_enter+0x2d/0x40 [ 95.500400] do_idle+0x1e5/0x240 [
    95.501385] cpu_startup_entry+0x29/0x30 [ 95.502422] start_secondary+0x11c/0x140 [ 95.503454]
    common_startup_64+0x13e/0x141 [ 95.504466] </TASK> [ 95.505197] Modules linked in: nft_fib_inet
    nft_fib_ipv4 nft_fib_ipv6 nft_fib nft_reject_inet nf_reject_ipv4 nf_reject_ipv6 nft_reject nft_ct
    nft_chain_nat nf_nat nf_conntrack nf_defrag_ip ---truncated--- (CVE-2024-40923)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40923");

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
  },
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
