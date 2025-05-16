#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225260);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48974");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48974");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: conntrack: fix using
    __this_cpu_add in preemptible Currently in nf_conntrack_hash_check_insert(), when it fails in
    nf_ct_ext_valid_pre/post(), NF_CT_STAT_INC() will be called in the preemptible context, a call trace can
    be triggered: BUG: using __this_cpu_add() in preemptible [00000000] code: conntrack/1636 caller is
    nf_conntrack_hash_check_insert+0x45/0x430 [nf_conntrack] Call Trace: <TASK> dump_stack_lvl+0x33/0x46
    check_preemption_disabled+0xc3/0xf0 nf_conntrack_hash_check_insert+0x45/0x430 [nf_conntrack]
    ctnetlink_create_conntrack+0x3cd/0x4e0 [nf_conntrack_netlink] ctnetlink_new_conntrack+0x1c0/0x450
    [nf_conntrack_netlink] nfnetlink_rcv_msg+0x277/0x2f0 [nfnetlink] netlink_rcv_skb+0x50/0x100
    nfnetlink_rcv+0x65/0x144 [nfnetlink] netlink_unicast+0x1ae/0x290 netlink_sendmsg+0x257/0x4f0
    sock_sendmsg+0x5f/0x70 This patch is to fix it by changing to use NF_CT_STAT_INC_ATOMIC() for
    nf_ct_ext_valid_pre/post() check in nf_conntrack_hash_check_insert(), as well as nf_ct_ext_valid_post() in
    __nf_conntrack_confirm(). Note that nf_ct_ext_valid_pre() check in __nf_conntrack_confirm() is safe to use
    NF_CT_STAT_INC(), as it's under local_bh_disable(). (CVE-2022-48974)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48974");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
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
