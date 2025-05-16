#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227452);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26600");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26600");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: phy: ti: phy-omap-usb2: Fix NULL
    pointer dereference for SRP If the external phy working together with phy-omap-usb2 does not implement
    send_srp(), we may still attempt to call it. This can happen on an idle Ethernet gadget triggering a
    wakeup for example: configfs-gadget.g1 gadget.0: ECM Suspend configfs-gadget.g1 gadget.0: Port suspended.
    Triggering wakeup ... Unable to handle kernel NULL pointer dereference at virtual address 00000000 when
    execute ... PC is at 0x0 LR is at musb_gadget_wakeup+0x1d4/0x254 [musb_hdrc] ... musb_gadget_wakeup
    [musb_hdrc] from usb_gadget_wakeup+0x1c/0x3c [udc_core] usb_gadget_wakeup [udc_core] from
    eth_start_xmit+0x3b0/0x3d4 [u_ether] eth_start_xmit [u_ether] from dev_hard_start_xmit+0x94/0x24c
    dev_hard_start_xmit from sch_direct_xmit+0x104/0x2e4 sch_direct_xmit from __dev_queue_xmit+0x334/0xd88
    __dev_queue_xmit from arp_solicit+0xf0/0x268 arp_solicit from neigh_probe+0x54/0x7c neigh_probe from
    __neigh_event_send+0x22c/0x47c __neigh_event_send from neigh_resolve_output+0x14c/0x1c0
    neigh_resolve_output from ip_finish_output2+0x1c8/0x628 ip_finish_output2 from ip_send_skb+0x40/0xd8
    ip_send_skb from udp_send_skb+0x124/0x340 udp_send_skb from udp_sendmsg+0x780/0x984 udp_sendmsg from
    __sys_sendto+0xd8/0x158 __sys_sendto from ret_fast_syscall+0x0/0x58 Let's fix the issue by checking for
    send_srp() and set_vbus() before calling them. For USB peripheral only cases these both could be NULL.
    (CVE-2024-26600)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26600");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
