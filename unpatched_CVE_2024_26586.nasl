#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227463);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26586");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26586");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix stack
    corruption When tc filters are first added to a net device, the corresponding local port gets bound to an
    ACL group in the device. The group contains a list of ACLs. In turn, each ACL points to a different TCAM
    region where the filters are stored. During forwarding, the ACLs are sequentially evaluated until a match
    is found. One reason to place filters in different regions is when they are added with decreasing
    priorities and in an alternating order so that two consecutive filters can never fit in the same region
    because of their key usage. In Spectrum-2 and newer ASICs the firmware started to report that the maximum
    number of ACLs in a group is more than 16, but the layout of the register that configures ACL groups
    (PAGT) was not updated to account for that. It is therefore possible to hit stack corruption [1] in the
    rare case where more than 16 ACLs in a group are required. Fix by limiting the maximum ACL group size to
    the minimum between what the firmware reports and the maximum ACLs that fit in the PAGT register. Add a
    test case to make sure the machine does not crash when this condition is hit. [1] Kernel panic - not
    syncing: stack-protector: Kernel stack is corrupted in: mlxsw_sp_acl_tcam_group_update+0x116/0x120 [...]
    dump_stack_lvl+0x36/0x50 panic+0x305/0x330 __stack_chk_fail+0x15/0x20
    mlxsw_sp_acl_tcam_group_update+0x116/0x120 mlxsw_sp_acl_tcam_group_region_attach+0x69/0x110
    mlxsw_sp_acl_tcam_vchunk_get+0x492/0xa20 mlxsw_sp_acl_tcam_ventry_add+0x25/0xe0
    mlxsw_sp_acl_rule_add+0x47/0x240 mlxsw_sp_flower_replace+0x1a9/0x1d0 tc_setup_cb_add+0xdc/0x1c0
    fl_hw_replace_filter+0x146/0x1f0 fl_change+0xc17/0x1360 tc_new_tfilter+0x472/0xb90
    rtnetlink_rcv_msg+0x313/0x3b0 netlink_rcv_skb+0x58/0x100 netlink_unicast+0x244/0x390
    netlink_sendmsg+0x1e4/0x440 ____sys_sendmsg+0x164/0x260 ___sys_sendmsg+0x9a/0xe0 __sys_sendmsg+0x7a/0xc0
    do_syscall_64+0x40/0xe0 entry_SYSCALL_64_after_hwframe+0x63/0x6b (CVE-2024-26586)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26586");

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
