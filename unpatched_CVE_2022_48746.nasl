#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225242);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48746");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48746");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: Fix handling of wrong
    devices during bond netevent Current implementation of bond netevent handler only check if the handled
    netdev is VF representor and it missing a check if the VF representor is on the same phys device of the
    bond handling the netevent. Fix by adding the missing check and optimizing the check if the netdev is VF
    representor so it will not access uninitialized private data and crashes. BUG: kernel NULL pointer
    dereference, address: 000000000000036c PGD 0 P4D 0 Oops: 0000 [#1] SMP NOPTI Workqueue: eth3bond0
    bond_mii_monitor [bonding] RIP: 0010:mlx5e_is_uplink_rep+0xc/0x50 [mlx5_core] RSP: 0018:ffff88812d69fd60
    EFLAGS: 00010282 RAX: 0000000000000000 RBX: ffff8881cf800000 RCX: 0000000000000000 RDX: ffff88812d69fe10
    RSI: 000000000000001b RDI: ffff8881cf800880 RBP: ffff8881cf800000 R08: 00000445cabccf2b R09:
    0000000000000008 R10: 0000000000000004 R11: 0000000000000008 R12: ffff88812d69fe10 R13: 00000000fffffffe
    R14: ffff88820c0f9000 R15: 0000000000000000 FS: 0000000000000000(0000) GS:ffff88846fb00000(0000)
    knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000000000000036c CR3:
    0000000103d80006 CR4: 0000000000370ea0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
    DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace:
    mlx5e_eswitch_uplink_rep+0x31/0x40 [mlx5_core] mlx5e_rep_is_lag_netdev+0x94/0xc0 [mlx5_core]
    mlx5e_rep_esw_bond_netevent+0xeb/0x3d0 [mlx5_core] raw_notifier_call_chain+0x41/0x60
    call_netdevice_notifiers_info+0x34/0x80 netdev_lower_state_changed+0x4e/0xa0 bond_mii_monitor+0x56b/0x640
    [bonding] process_one_work+0x1b9/0x390 worker_thread+0x4d/0x3d0 ? rescuer_thread+0x350/0x350
    kthread+0x124/0x150 ? set_kthread_struct+0x40/0x40 ret_from_fork+0x1f/0x30 (CVE-2022-48746)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
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
