#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229362);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35855");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35855");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix possible
    use-after-free during activity update The rule activity update delayed work periodically traverses the
    list of configured rules and queries their activity from the device. As part of this task it accesses the
    entry pointed by 'ventry->entry', but this entry can be changed concurrently by the rehash delayed work,
    leading to a use-after-free [1]. Fix by closing the race and perform the activity query under the
    'vregion->lock' mutex. [1] BUG: KASAN: slab-use-after-free in
    mlxsw_sp_acl_tcam_flower_rule_activity_get+0x121/0x140 Read of size 8 at addr ffff8881054ed808 by task
    kworker/0:18/181 CPU: 0 PID: 181 Comm: kworker/0:18 Not tainted 6.9.0-rc2-custom-00781-gd5ab772d32f7 #2
    Hardware name: Mellanox Technologies Ltd. MSN3700/VMOD0005, BIOS 5.11 01/06/2019 Workqueue: mlxsw_core
    mlxsw_sp_acl_rule_activity_update_work Call Trace: <TASK> dump_stack_lvl+0xc6/0x120
    print_report+0xce/0x670 kasan_report+0xd7/0x110 mlxsw_sp_acl_tcam_flower_rule_activity_get+0x121/0x140
    mlxsw_sp_acl_rule_activity_update_work+0x219/0x400 process_one_work+0x8eb/0x19b0 worker_thread+0x6c9/0xf70
    kthread+0x2c9/0x3b0 ret_from_fork+0x4d/0x80 ret_from_fork_asm+0x1a/0x30 </TASK> Allocated by task 1039:
    kasan_save_stack+0x33/0x60 kasan_save_track+0x14/0x30 __kasan_kmalloc+0x8f/0xa0 __kmalloc+0x19c/0x360
    mlxsw_sp_acl_tcam_entry_create+0x7b/0x1f0 mlxsw_sp_acl_tcam_vchunk_migrate_all+0x30d/0xb50
    mlxsw_sp_acl_tcam_vregion_rehash_work+0x157/0x1300 process_one_work+0x8eb/0x19b0 worker_thread+0x6c9/0xf70
    kthread+0x2c9/0x3b0 ret_from_fork+0x4d/0x80 ret_from_fork_asm+0x1a/0x30 Freed by task 1039:
    kasan_save_stack+0x33/0x60 kasan_save_track+0x14/0x30 kasan_save_free_info+0x3b/0x60
    poison_slab_object+0x102/0x170 __kasan_slab_free+0x14/0x30 kfree+0xc1/0x290
    mlxsw_sp_acl_tcam_vchunk_migrate_all+0x3d7/0xb50 mlxsw_sp_acl_tcam_vregion_rehash_work+0x157/0x1300
    process_one_work+0x8eb/0x19b0 worker_thread+0x6c9/0xf70 kthread+0x2c9/0x3b0 ret_from_fork+0x4d/0x80
    ret_from_fork_asm+0x1a/0x30 (CVE-2024-35855)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35855");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/10");
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
