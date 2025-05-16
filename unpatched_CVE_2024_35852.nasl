#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229589);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35852");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35852");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix memory
    leak when canceling rehash work The rehash delayed work is rescheduled with a delay if the number of
    credits at end of the work is not negative as supposedly it means that the migration ended. Otherwise, it
    is rescheduled immediately. After mlxsw: spectrum_acl_tcam: Fix possible use-after-free during rehash
    the above is no longer accurate as a non-negative number of credits is no longer indicative of the
    migration being done. It can also happen if the work encountered an error in which case the migration will
    resume the next time the work is scheduled. The significance of the above is that it is possible for the
    work to be pending and associated with hints that were allocated when the migration started. This leads to
    the hints being leaked [1] when the work is canceled while pending as part of ACL region dismantle. Fix by
    freeing the hints if hints are associated with a work that was canceled while pending. Blame the original
    commit since the reliance on not having a pending work associated with hints is fragile. [1] unreferenced
    object 0xffff88810e7c3000 (size 256): comm kworker/0:16, pid 176, jiffies 4295460353 hex dump (first 32
    bytes): 00 30 95 11 81 88 ff ff 61 00 00 00 00 00 00 80 .0......a....... 00 00 61 00 40 00 00 00 00 00 00
    00 04 00 00 00 ..a.@........... backtrace (crc 2544ddb9): [<00000000cf8cfab3>] kmalloc_trace+0x23f/0x2a0
    [<000000004d9a1ad9>] objagg_hints_get+0x42/0x390 [<000000000b143cf3>]
    mlxsw_sp_acl_erp_rehash_hints_get+0xca/0x400 [<0000000059bdb60a>]
    mlxsw_sp_acl_tcam_vregion_rehash_work+0x868/0x1160 [<00000000e81fd734>] process_one_work+0x59c/0xf20
    [<00000000ceee9e81>] worker_thread+0x799/0x12c0 [<00000000bda6fe39>] kthread+0x246/0x300
    [<0000000070056d23>] ret_from_fork+0x34/0x70 [<00000000dea2b93e>] ret_from_fork_asm+0x1a/0x30
    (CVE-2024-35852)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35852");

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
