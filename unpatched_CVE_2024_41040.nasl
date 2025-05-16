#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229595);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41040");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41040");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/sched: Fix UAF when resolving a
    clash KASAN reports the following UAF: BUG: KASAN: slab-use-after-free in
    tcf_ct_flow_table_process_conn+0x12b/0x380 [act_ct] Read of size 1 at addr ffff888c07603600 by task
    handler130/6469 Call Trace: <IRQ> dump_stack_lvl+0x48/0x70
    print_address_description.constprop.0+0x33/0x3d0 print_report+0xc0/0x2b0 kasan_report+0xd0/0x120
    __asan_load1+0x6c/0x80 tcf_ct_flow_table_process_conn+0x12b/0x380 [act_ct] tcf_ct_act+0x886/0x1350
    [act_ct] tcf_action_exec+0xf8/0x1f0 fl_classify+0x355/0x360 [cls_flower] __tcf_classify+0x1fd/0x330
    tcf_classify+0x21c/0x3c0 sch_handle_ingress.constprop.0+0x2c5/0x500
    __netif_receive_skb_core.constprop.0+0xb25/0x1510 __netif_receive_skb_list_core+0x220/0x4c0
    netif_receive_skb_list_internal+0x446/0x620 napi_complete_done+0x157/0x3d0 gro_cell_poll+0xcf/0x100
    __napi_poll+0x65/0x310 net_rx_action+0x30c/0x5c0 __do_softirq+0x14f/0x491 __irq_exit_rcu+0x82/0xc0
    irq_exit_rcu+0xe/0x20 common_interrupt+0xa1/0xb0 </IRQ> <TASK> asm_common_interrupt+0x27/0x40 Allocated by
    task 6469: kasan_save_stack+0x38/0x70 kasan_set_track+0x25/0x40 kasan_save_alloc_info+0x1e/0x40
    __kasan_krealloc+0x133/0x190 krealloc+0xaa/0x130 nf_ct_ext_add+0xed/0x230 [nf_conntrack]
    tcf_ct_act+0x1095/0x1350 [act_ct] tcf_action_exec+0xf8/0x1f0 fl_classify+0x355/0x360 [cls_flower]
    __tcf_classify+0x1fd/0x330 tcf_classify+0x21c/0x3c0 sch_handle_ingress.constprop.0+0x2c5/0x500
    __netif_receive_skb_core.constprop.0+0xb25/0x1510 __netif_receive_skb_list_core+0x220/0x4c0
    netif_receive_skb_list_internal+0x446/0x620 napi_complete_done+0x157/0x3d0 gro_cell_poll+0xcf/0x100
    __napi_poll+0x65/0x310 net_rx_action+0x30c/0x5c0 __do_softirq+0x14f/0x491 Freed by task 6469:
    kasan_save_stack+0x38/0x70 kasan_set_track+0x25/0x40 kasan_save_free_info+0x2b/0x60
    ____kasan_slab_free+0x180/0x1f0 __kasan_slab_free+0x12/0x30 slab_free_freelist_hook+0xd2/0x1a0
    __kmem_cache_free+0x1a2/0x2f0 kfree+0x78/0x120 nf_conntrack_free+0x74/0x130 [nf_conntrack]
    nf_ct_destroy+0xb2/0x140 [nf_conntrack] __nf_ct_resolve_clash+0x529/0x5d0 [nf_conntrack]
    nf_ct_resolve_clash+0xf6/0x490 [nf_conntrack] __nf_conntrack_confirm+0x2c6/0x770 [nf_conntrack]
    tcf_ct_act+0x12ad/0x1350 [act_ct] tcf_action_exec+0xf8/0x1f0 fl_classify+0x355/0x360 [cls_flower]
    __tcf_classify+0x1fd/0x330 tcf_classify+0x21c/0x3c0 sch_handle_ingress.constprop.0+0x2c5/0x500
    __netif_receive_skb_core.constprop.0+0xb25/0x1510 __netif_receive_skb_list_core+0x220/0x4c0
    netif_receive_skb_list_internal+0x446/0x620 napi_complete_done+0x157/0x3d0 gro_cell_poll+0xcf/0x100
    __napi_poll+0x65/0x310 net_rx_action+0x30c/0x5c0 __do_softirq+0x14f/0x491 The ct may be dropped if a clash
    has been resolved but is still passed to the tcf_ct_flow_table_process_conn function for further usage.
    This issue can be fixed by retrieving ct from skb again after confirming conntrack. (CVE-2024-41040)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41040");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
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
