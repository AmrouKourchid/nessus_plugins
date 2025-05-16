#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225693);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49017");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49017");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tipc: re-fetch skb cb after
    tipc_msg_validate As the call trace shows, the original skb was freed in tipc_msg_validate(), and
    dereferencing the old skb cb would cause an use-after-free crash. BUG: KASAN: use-after-free in
    tipc_crypto_rcv_complete+0x1835/0x2240 [tipc] Call Trace: <IRQ> tipc_crypto_rcv_complete+0x1835/0x2240
    [tipc] tipc_crypto_rcv+0xd32/0x1ec0 [tipc] tipc_rcv+0x744/0x1150 [tipc] ... Allocated by task 47078:
    kmem_cache_alloc_node+0x158/0x4d0 __alloc_skb+0x1c1/0x270 tipc_buf_acquire+0x1e/0xe0 [tipc]
    tipc_msg_create+0x33/0x1c0 [tipc] tipc_link_build_proto_msg+0x38a/0x2100 [tipc]
    tipc_link_timeout+0x8b8/0xef0 [tipc] tipc_node_timeout+0x2a1/0x960 [tipc] call_timer_fn+0x2d/0x1c0 ...
    Freed by task 47078: tipc_msg_validate+0x7b/0x440 [tipc] tipc_crypto_rcv_complete+0x4b5/0x2240 [tipc]
    tipc_crypto_rcv+0xd32/0x1ec0 [tipc] tipc_rcv+0x744/0x1150 [tipc] This patch fixes it by re-fetching the
    skb cb from the new allocated skb after calling tipc_msg_validate(). (CVE-2022-49017)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
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
