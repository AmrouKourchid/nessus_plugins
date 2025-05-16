#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230163);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47162");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47162");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tipc: skb_linearize the head skb when
    reassembling msgs It's not a good idea to append the frag skb to a skb's frag_list if the frag_list
    already has skbs from elsewhere, such as this skb was created by pskb_copy() where the frag_list was
    cloned (all the skbs in it were skb_get'ed) and shared by multiple skbs. However, the new appended frag
    skb should have been only seen by the current skb. Otherwise, it will cause use after free crashes as this
    appended frag skb are seen by multiple skbs but it only got skb_get called once. The same thing happens
    with a skb updated by pskb_may_pull() with a skb_cloned skb. Li Shuang has reported quite a few crashes
    caused by this when doing testing over macvlan devices: [] kernel BUG at net/core/skbuff.c:1970! [] Call
    Trace: [] skb_clone+0x4d/0xb0 [] macvlan_broadcast+0xd8/0x160 [macvlan] []
    macvlan_process_broadcast+0x148/0x150 [macvlan] [] process_one_work+0x1a7/0x360 []
    worker_thread+0x30/0x390 [] kernel BUG at mm/usercopy.c:102! [] Call Trace: []
    __check_heap_object+0xd3/0x100 [] __check_object_size+0xff/0x16b [] simple_copy_to_iter+0x1c/0x30 []
    __skb_datagram_iter+0x7d/0x310 [] __skb_datagram_iter+0x2a5/0x310 [] skb_copy_datagram_iter+0x3b/0x90 []
    tipc_recvmsg+0x14a/0x3a0 [tipc] [] ____sys_recvmsg+0x91/0x150 [] ___sys_recvmsg+0x7b/0xc0 [] kernel BUG at
    mm/slub.c:305! [] Call Trace: [] <IRQ> [] kmem_cache_free+0x3ff/0x400 []
    __netif_receive_skb_core+0x12c/0xc40 [] ? kmem_cache_alloc+0x12e/0x270 []
    netif_receive_skb_internal+0x3d/0xb0 [] ? get_rx_page_info+0x8e/0xa0 [be2net] [] be_poll+0x6ef/0xd00
    [be2net] [] ? irq_exit+0x4f/0x100 [] net_rx_action+0x149/0x3b0 ... This patch is to fix it by linearizing
    the head skb if it has frag_list set in tipc_buf_append(). Note that we choose to do this before calling
    skb_unshare(), as __skb_linearize() will avoid skb_copy(). Also, we can not just drop the frag_list either
    as the early time. (CVE-2021-47162)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47162");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
