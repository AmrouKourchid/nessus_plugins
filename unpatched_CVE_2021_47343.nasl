#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224461);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47343");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47343");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: dm btree remove: assign new_root only
    when removal succeeds remove_raw() in dm_btree_remove() may fail due to IO read error (e.g. read the
    content of origin block fails during shadowing), and the value of shadow_spine::root is uninitialized, but
    the uninitialized value is still assign to new_root in the end of dm_btree_remove(). For dm-thin, the
    value of pmd->details_root or pmd->root will become an uninitialized value, so if trying to read
    details_info tree again out-of-bound memory may occur as showed below: general protection fault, probably
    for non-canonical address 0x3fdcb14c8d7520 CPU: 4 PID: 515 Comm: dmsetup Not tainted 5.13.0-rc6 Hardware
    name: QEMU Standard PC RIP: 0010:metadata_ll_load_ie+0x14/0x30 Call Trace:
    sm_metadata_count_is_more_than_one+0xb9/0xe0 dm_tm_shadow_block+0x52/0x1c0 shadow_step+0x59/0xf0
    remove_raw+0xb2/0x170 dm_btree_remove+0xf4/0x1c0 dm_pool_delete_thin_device+0xc3/0x140
    pool_message+0x218/0x2b0 target_message+0x251/0x290 ctl_ioctl+0x1c4/0x4d0 dm_ctl_ioctl+0xe/0x20
    __x64_sys_ioctl+0x7b/0xb0 do_syscall_64+0x40/0xb0 entry_SYSCALL_64_after_hwframe+0x44/0xae Fixing it by
    only assign new_root when removal succeeds (CVE-2021-47343)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47343");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
