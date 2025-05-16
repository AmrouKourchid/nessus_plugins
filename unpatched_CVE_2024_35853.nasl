#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229355);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35853");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35853");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix memory
    leak during rehash The rehash delayed work migrates filters from one region to another. This is done by
    iterating over all chunks (all the filters with the same priority) in the region and in each chunk
    iterating over all the filters. If the migration fails, the code tries to migrate the filters back to the
    old region. However, the rollback itself can also fail in which case another migration will be erroneously
    performed. Besides the fact that this ping pong is not a very good idea, it also creates a problem. Each
    virtual chunk references two chunks: The currently used one ('vchunk->chunk') and a backup
    ('vchunk->chunk2'). During migration the first holds the chunk we want to migrate filters to and the
    second holds the chunk we are migrating filters from. The code currently assumes - but does not verify -
    that the backup chunk does not exist (NULL) if the currently used chunk does not reference the target
    region. This assumption breaks when we are trying to rollback a rollback, resulting in the backup chunk
    being overwritten and leaked [1]. Fix by not rolling back a failed rollback and add a warning to avoid
    future cases. [1] WARNING: CPU: 5 PID: 1063 at lib/parman.c:291 parman_destroy+0x17/0x20 Modules linked
    in: CPU: 5 PID: 1063 Comm: kworker/5:11 Tainted: G W 6.9.0-rc2-custom-00784-gc6a05c468a0b #14 Hardware
    name: Mellanox Technologies Ltd. MSN3700/VMOD0005, BIOS 5.11 01/06/2019 Workqueue: mlxsw_core
    mlxsw_sp_acl_tcam_vregion_rehash_work RIP: 0010:parman_destroy+0x17/0x20 [...] Call Trace: <TASK>
    mlxsw_sp_acl_atcam_region_fini+0x19/0x60 mlxsw_sp_acl_tcam_region_destroy+0x49/0xf0
    mlxsw_sp_acl_tcam_vregion_rehash_work+0x1f1/0x470 process_one_work+0x151/0x370 worker_thread+0x2cb/0x3e0
    kthread+0xd0/0x100 ret_from_fork+0x34/0x50 ret_from_fork_asm+0x1a/0x30 </TASK> (CVE-2024-35853)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35853");

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
