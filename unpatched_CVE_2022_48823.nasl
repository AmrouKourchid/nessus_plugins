#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225661);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48823");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48823");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: qedf: Fix refcount issue when
    LOGO is received during TMF Hung task call trace was seen during LOGO processing. [ 974.309060]
    [0000:00:00.0]:[qedf_eh_device_reset:868]: 1:0:2:0: LUN RESET Issued... [ 974.309065]
    [0000:00:00.0]:[qedf_initiate_tmf:2422]: tm_flags 0x10 sc_cmd 00000000c16b930f op = 0x2a target_id = 0x2
    lun=0 [ 974.309178] [0000:00:00.0]:[qedf_initiate_tmf:2431]: portid=016900 tm_flags =LUN RESET [
    974.309222] [0000:00:00.0]:[qedf_initiate_tmf:2438]: orig io_req = 00000000ec78df8f xid = 0x180 ref_cnt =
    1. [ 974.309625] host1: rport 016900: Received LOGO request while in state Ready [ 974.309627] host1:
    rport 016900: Delete port [ 974.309642] host1: rport 016900: work event 3 [ 974.309644] host1: rport
    016900: lld callback ev 3 [ 974.313243] [0000:61:00.2]:[qedf_execute_tmf:2383]:1: fcport is uploading, not
    executing flush. [ 974.313295] [0000:61:00.2]:[qedf_execute_tmf:2400]:1: task mgmt command success... [
    984.031088] INFO: task jbd2/dm-15-8:7645 blocked for more than 120 seconds. [ 984.031136] Not tainted
    4.18.0-305.el8.x86_64 #1 [ 984.031166] echo 0 > /proc/sys/kernel/hung_task_timeout_secs disables this
    message. [ 984.031209] jbd2/dm-15-8 D 0 7645 2 0x80004080 [ 984.031212] Call Trace: [ 984.031222]
    __schedule+0x2c4/0x700 [ 984.031230] ? unfreeze_partials.isra.83+0x16e/0x1a0 [ 984.031233] ?
    bit_wait_timeout+0x90/0x90 [ 984.031235] schedule+0x38/0xa0 [ 984.031238] io_schedule+0x12/0x40 [
    984.031240] bit_wait_io+0xd/0x50 [ 984.031243] __wait_on_bit+0x6c/0x80 [ 984.031248] ?
    free_buffer_head+0x21/0x50 [ 984.031251] out_of_line_wait_on_bit+0x91/0xb0 [ 984.031257] ?
    init_wait_var_entry+0x50/0x50 [ 984.031268] jbd2_journal_commit_transaction+0x112e/0x19f0 [jbd2] [
    984.031280] kjournald2+0xbd/0x270 [jbd2] [ 984.031284] ? finish_wait+0x80/0x80 [ 984.031291] ?
    commit_timeout+0x10/0x10 [jbd2] [ 984.031294] kthread+0x116/0x130 [ 984.031300] ?
    kthread_flush_work_fn+0x10/0x10 [ 984.031305] ret_from_fork+0x1f/0x40 There was a ref count issue when
    LOGO is received during TMF. This leads to one of the I/Os hanging with the driver. Fix the ref count.
    (CVE-2022-48823)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48823");

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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
