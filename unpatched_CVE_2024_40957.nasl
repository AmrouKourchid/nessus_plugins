#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228461);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40957");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40957");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: seg6: fix parameter passing when
    calling NF_HOOK() in End.DX4 and End.DX6 behaviors input_action_end_dx4() and input_action_end_dx6() are
    called NF_HOOK() for PREROUTING hook, in PREROUTING hook, we should passing a valid indev, and a NULL
    outdev to NF_HOOK(), otherwise may trigger a NULL pointer dereference, as below: [74830.647293] BUG:
    kernel NULL pointer dereference, address: 0000000000000090 [74830.655633] #PF: supervisor read access in
    kernel mode [74830.657888] #PF: error_code(0x0000) - not-present page [74830.659500] PGD 0 P4D 0
    [74830.660450] Oops: 0000 [#1] PREEMPT SMP PTI ... [74830.664953] Hardware name: Red Hat KVM, BIOS 0.5.1
    01/01/2011 [74830.666569] RIP: 0010:rpfilter_mt+0x44/0x15e [ipt_rpfilter] ... [74830.689725] Call Trace:
    [74830.690402] <IRQ> [74830.690953] ? show_trace_log_lvl+0x1c4/0x2df [74830.692020] ?
    show_trace_log_lvl+0x1c4/0x2df [74830.693095] ? ipt_do_table+0x286/0x710 [ip_tables] [74830.694275] ?
    __die_body.cold+0x8/0xd [74830.695205] ? page_fault_oops+0xac/0x140 [74830.696244] ?
    exc_page_fault+0x62/0x150 [74830.697225] ? asm_exc_page_fault+0x22/0x30 [74830.698344] ?
    rpfilter_mt+0x44/0x15e [ipt_rpfilter] [74830.699540] ipt_do_table+0x286/0x710 [ip_tables] [74830.700758] ?
    ip6_route_input+0x19d/0x240 [74830.701752] nf_hook_slow+0x3f/0xb0 [74830.702678]
    input_action_end_dx4+0x19b/0x1e0 [74830.703735] ? input_action_end_t+0xe0/0xe0 [74830.704734]
    seg6_local_input_core+0x2d/0x60 [74830.705782] lwtunnel_input+0x5b/0xb0 [74830.706690]
    __netif_receive_skb_one_core+0x63/0xa0 [74830.707825] process_backlog+0x99/0x140 [74830.709538]
    __napi_poll+0x2c/0x160 [74830.710673] net_rx_action+0x296/0x350 [74830.711860] __do_softirq+0xcb/0x2ac
    [74830.713049] do_softirq+0x63/0x90 input_action_end_dx4() passing a NULL indev to NF_HOOK(), and finally
    trigger a NULL dereference in rpfilter_mt()->rpfilter_is_loopback(): static bool
    rpfilter_is_loopback(const struct sk_buff *skb, const struct net_device *in) { // in is NULL return
    skb->pkt_type == PACKET_LOOPBACK || in->flags & IFF_LOOPBACK; } (CVE-2024-40957)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40957");

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
