#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226090);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52580");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52580");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/core: Fix ETH_P_1588 flow
    dissector When a PTP ethernet raw frame with a size of more than 256 bytes followed by a 0xff pattern is
    sent to __skb_flow_dissect, nhoff value calculation is wrong. For example: hdr->message_length takes the
    wrong value (0xffff) and it does not replicate real header length. In this case, 'nhoff' value was
    overridden and the PTP header was badly dissected. This leads to a kernel crash. net/core: flow_dissector
    net/core flow dissector nhoff = 0x0000000e net/core flow dissector hdr->message_length = 0x0000ffff
    net/core flow dissector nhoff = 0x0001000d (u16 overflow) ... skb linear: 00000000: 00 a0 c9 00 00 00 00
    a0 c9 00 00 00 88 skb frag: 00000000: f7 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff Using the size of
    the ptp_header struct will allow the corrected calculation of the nhoff value. net/core flow dissector
    nhoff = 0x0000000e net/core flow dissector nhoff = 0x00000030 (sizeof ptp_header) ... skb linear:
    00000000: 00 a0 c9 00 00 00 00 a0 c9 00 00 00 88 f7 ff ff skb linear: 00000010: ff ff ff ff ff ff ff ff ff
    ff ff ff ff ff ff ff skb linear: 00000020: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff skb frag:
    00000000: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff Kernel trace: [ 74.984279] ------------[ cut
    here ]------------ [ 74.989471] kernel BUG at include/linux/skbuff.h:2440! [ 74.995237] invalid opcode:
    0000 [#1] PREEMPT SMP NOPTI [ 75.001098] CPU: 4 PID: 0 Comm: swapper/4 Tainted: G U 5.15.85-intel-ese-
    standard-lts #1 [ 75.011629] Hardware name: Intel Corporation A-Island (CPU:AlderLake)/A-Island (ID:06),
    BIOS SB_ADLP.01.01.00.01.03.008.D-6A9D9E73-dirty Mar 30 2023 [ 75.026507] RIP:
    0010:eth_type_trans+0xd0/0x130 [ 75.031594] Code: 03 88 47 78 eb c7 8b 47 68 2b 47 6c 48 8b 97 c0 00 00 00
    83 f8 01 7e 1b 48 85 d2 74 06 66 83 3a ff 74 09 b8 00 04 00 00 eb ab <0f> 0b b8 00 01 00 00 eb a2 48 85 ff
    74 eb 48 8d 54 24 06 31 f6 b9 [ 75.052612] RSP: 0018:ffff9948c0228de0 EFLAGS: 00010297 [ 75.058473] RAX:
    00000000000003f2 RBX: ffff8e47047dc300 RCX: 0000000000001003 [ 75.066462] RDX: ffff8e4e8c9ea040 RSI:
    ffff8e4704e0a000 RDI: ffff8e47047dc300 [ 75.074458] RBP: ffff8e4704e2acc0 R08: 00000000000003f3 R09:
    0000000000000800 [ 75.082466] R10: 000000000000000d R11: ffff9948c0228dec R12: ffff8e4715e4e010 [
    75.090461] R13: ffff9948c0545018 R14: 0000000000000001 R15: 0000000000000800 [ 75.098464] FS:
    0000000000000000(0000) GS:ffff8e4e8fb00000(0000) knlGS:0000000000000000 [ 75.107530] CS: 0010 DS: 0000 ES:
    0000 CR0: 0000000080050033 [ 75.113982] CR2: 00007f5eb35934a0 CR3: 0000000150e0a002 CR4: 0000000000770ee0
    [ 75.121980] PKRU: 55555554 [ 75.125035] Call Trace: [ 75.127792] <IRQ> [ 75.130063] ?
    eth_get_headlen+0xa4/0xc0 [ 75.134472] igc_process_skb_fields+0xcd/0x150 [ 75.139461]
    igc_poll+0xc80/0x17b0 [ 75.143272] __napi_poll+0x27/0x170 [ 75.147192] net_rx_action+0x234/0x280 [
    75.151409] __do_softirq+0xef/0x2f4 [ 75.155424] irq_exit_rcu+0xc7/0x110 [ 75.159432]
    common_interrupt+0xb8/0xd0 [ 75.163748] </IRQ> [ 75.166112] <TASK> [ 75.168473]
    asm_common_interrupt+0x22/0x40 [ 75.173175] RIP: 0010:cpuidle_enter_state+0xe2/0x350 [ 75.178749] Code: 85
    c0 0f 8f 04 02 00 00 31 ff e8 39 6c 67 ff 45 84 ff 74 12 9c 58 f6 c4 02 0f 85 50 02 00 00 31 ff e8 52 b0
    6d ff fb 45 85 f6 <0f> 88 b1 00 00 00 49 63 ce 4c 2b 2c 24 48 89 c8 48 6b d1 68 48 c1 [ 75.199757] RSP:
    0018:ffff9948c013bea8 EFLAGS: 00000202 [ 75.205614] RAX: ffff8e4e8fb00000 RBX: ffffb948bfd23900 RCX:
    000000000000001f [ 75.213619] RDX: 0000000000000004 RSI: ffffffff94206161 RDI: ffffffff94212e20 [
    75.221620] RBP: 0000000000000004 R08: 000000117568973a R09: 0000000000000001 [ 75.229622] R10:
    000000000000afc8 R11: ffff8e4e8fb29ce4 R12: ffffffff945ae980 [ 75.237628] R13: 000000117568973a R14:
    0000000000000004 R15: 0000000000000000 [ 75.245635] ? ---truncated--- (CVE-2023-52580)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52580");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/12");
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
