#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228178);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26611");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26611");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: xsk: fix usage of multi-buffer BPF
    helpers for ZC XDP Currently when packet is shrunk via bpf_xdp_adjust_tail() and memory type is set to
    MEM_TYPE_XSK_BUFF_POOL, null ptr dereference happens: [1136314.192256] BUG: kernel NULL pointer
    dereference, address: 0000000000000034 [1136314.203943] #PF: supervisor read access in kernel mode
    [1136314.213768] #PF: error_code(0x0000) - not-present page [1136314.223550] PGD 0 P4D 0 [1136314.230684]
    Oops: 0000 [#1] PREEMPT SMP NOPTI [1136314.239621] CPU: 8 PID: 54203 Comm: xdpsock Not tainted 6.6.0+ #257
    [1136314.250469] Hardware name: Intel Corporation S2600WFT/S2600WFT, BIOS
    SE5C620.86B.02.01.0008.031920191559 03/19/2019 [1136314.265615] RIP: 0010:__xdp_return+0x6c/0x210
    [1136314.274653] Code: ad 00 48 8b 47 08 49 89 f8 a8 01 0f 85 9b 01 00 00 0f 1f 44 00 00 f0 41 ff 48 34 75
    32 4c 89 c7 e9 79 cd 80 ff 83 fe 03 75 17 <f6> 41 34 01 0f 85 02 01 00 00 48 89 cf e9 22 cc 1e 00 e9 3d d2
    86 [1136314.302907] RSP: 0018:ffffc900089f8db0 EFLAGS: 00010246 [1136314.312967] RAX: ffffc9003168aed0
    RBX: ffff8881c3300000 RCX: 0000000000000000 [1136314.324953] RDX: 0000000000000000 RSI: 0000000000000003
    RDI: ffffc9003168c000 [1136314.336929] RBP: 0000000000000ae0 R08: 0000000000000002 R09: 0000000000010000
    [1136314.348844] R10: ffffc9000e495000 R11: 0000000000000040 R12: 0000000000000001 [1136314.360706] R13:
    0000000000000524 R14: ffffc9003168aec0 R15: 0000000000000001 [1136314.373298] FS: 00007f8df8bbcb80(0000)
    GS:ffff8897e0e00000(0000) knlGS:0000000000000000 [1136314.386105] CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 [1136314.396532] CR2: 0000000000000034 CR3: 00000001aa912002 CR4: 00000000007706f0
    [1136314.408377] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [1136314.420173] DR3:
    0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [1136314.431890] PKRU: 55555554
    [1136314.439143] Call Trace: [1136314.446058] <IRQ> [1136314.452465] ? __die+0x20/0x70 [1136314.459881] ?
    page_fault_oops+0x15b/0x440 [1136314.468305] ? exc_page_fault+0x6a/0x150 [1136314.476491] ?
    asm_exc_page_fault+0x22/0x30 [1136314.484927] ? __xdp_return+0x6c/0x210 [1136314.492863]
    bpf_xdp_adjust_tail+0x155/0x1d0 [1136314.501269] bpf_prog_ccc47ae29d3b6570_xdp_sock_prog+0x15/0x60
    [1136314.511263] ice_clean_rx_irq_zc+0x206/0xc60 [ice] [1136314.520222] ? ice_xmit_zc+0x6e/0x150 [ice]
    [1136314.528506] ice_napi_poll+0x467/0x670 [ice] [1136314.536858] ?
    ttwu_do_activate.constprop.0+0x8f/0x1a0 [1136314.546010] __napi_poll+0x29/0x1b0 [1136314.553462]
    net_rx_action+0x133/0x270 [1136314.561619] __do_softirq+0xbe/0x28e [1136314.569303] do_softirq+0x3f/0x60
    This comes from __xdp_return() call with xdp_buff argument passed as NULL which is supposed to be consumed
    by xsk_buff_free() call. To address this properly, in ZC case, a node that represents the frag being
    removed has to be pulled out of xskb_list. Introduce appropriate xsk helpers to do such node operation and
    use them accordingly within bpf_xdp_adjust_tail(). (CVE-2024-26611)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26611");

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
