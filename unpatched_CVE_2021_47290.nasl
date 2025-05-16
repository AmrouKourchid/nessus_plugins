#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224365);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47290");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47290");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: target: Fix NULL dereference on
    XCOPY completion CPU affinity control added with commit 39ae3edda325 (scsi: target: core: Make completion
    affinity configurable) makes target_complete_cmd() queue work on a CPU based on
    se_tpg->se_tpg_wwn->cmd_compl_affinity state. LIO's EXTENDED COPY worker is a special case in that
    read/write cmds are dispatched using the global xcopy_pt_tpg, which carries a NULL se_tpg_wwn pointer
    following initialization in target_xcopy_setup_pt(). The NULL xcopy_pt_tpg->se_tpg_wwn pointer is
    dereferenced on completion of any EXTENDED COPY initiated read/write cmds. E.g using the libiscsi
    SCSI.ExtendedCopy.Simple test: BUG: kernel NULL pointer dereference, address: 00000000000001a8 RIP:
    0010:target_complete_cmd+0x9d/0x130 [target_core_mod] Call Trace: fd_execute_rw+0x148/0x42a
    [target_core_file] ? __dynamic_pr_debug+0xa7/0xe0 ? target_check_reservation+0x5b/0x940 [target_core_mod]
    __target_execute_cmd+0x1e/0x90 [target_core_mod] transport_generic_new_cmd+0x17c/0x330 [target_core_mod]
    target_xcopy_issue_pt_cmd+0x9/0x60 [target_core_mod] target_xcopy_read_source.isra.7+0x10b/0x1b0
    [target_core_mod] ? target_check_fua+0x40/0x40 [target_core_mod] ?
    transport_complete_task_attr+0x130/0x130 [target_core_mod] target_xcopy_do_work+0x61f/0xc00
    [target_core_mod] This fix makes target_complete_cmd() queue work on se_cmd->cpuid if se_tpg_wwn is NULL.
    (CVE-2021-47290)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47290");

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
       "match": {
        "os_version": "8"
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
