#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225416);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48651");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48651");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ipvlan: Fix out-of-bound bugs caused
    by unset skb->mac_header If an AF_PACKET socket is used to send packets through ipvlan and the default
    xmit function of the AF_PACKET socket is changed from dev_queue_xmit() to packet_direct_xmit() via
    setsockopt() with the option name of PACKET_QDISC_BYPASS, the skb->mac_header may not be reset and remains
    as the initial value of 65535, this may trigger slab-out-of-bounds bugs as following:
    ================================================================= UG: KASAN: slab-out-of-bounds in
    ipvlan_xmit_mode_l2+0xdb/0x330 [ipvlan] PU: 2 PID: 1768 Comm: raw_send Kdump: loaded Not tainted
    6.0.0-rc4+ #6 ardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-1.fc33 all Trace:
    print_address_description.constprop.0+0x1d/0x160 print_report.cold+0x4f/0x112 kasan_report+0xa3/0x130
    ipvlan_xmit_mode_l2+0xdb/0x330 [ipvlan] ipvlan_start_xmit+0x29/0xa0 [ipvlan] __dev_direct_xmit+0x2e2/0x380
    packet_direct_xmit+0x22/0x60 packet_snd+0x7c9/0xc40 sock_sendmsg+0x9a/0xa0 __sys_sendto+0x18a/0x230
    __x64_sys_sendto+0x74/0x90 do_syscall_64+0x3b/0x90 entry_SYSCALL_64_after_hwframe+0x63/0xcd The root cause
    is: 1. packet_snd() only reset skb->mac_header when sock->type is SOCK_RAW and skb->protocol is not
    specified as in packet_parse_headers() 2. packet_direct_xmit() doesn't reset skb->mac_header as
    dev_queue_xmit() In this case, skb->mac_header is 65535 when ipvlan_xmit_mode_l2() is called. So when
    ipvlan_xmit_mode_l2() gets mac header with eth_hdr() which use skb->head + skb->mac_header, out-of-bound
    access occurs. This patch replaces eth_hdr() with skb_eth_hdr() in ipvlan_xmit_mode_l2() and reset mac
    header in multicast to solve this out-of-bound bug. (CVE-2022-48651)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48651");

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
    "name": "linux-gcp-5.15",
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
        "os_version": "20.04"
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
