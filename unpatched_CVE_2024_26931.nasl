#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227531);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26931");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26931");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: qla2xxx: Fix command flush on
    cable pull System crash due to command failed to flush back to SCSI layer. BUG: unable to handle kernel
    NULL pointer dereference at 0000000000000000 PGD 0 P4D 0 Oops: 0000 [#1] SMP NOPTI CPU: 27 PID: 793455
    Comm: kworker/u130:6 Kdump: loaded Tainted: G OE --------- - - 4.18.0-372.9.1.el8.x86_64 #1 Hardware name:
    HPE ProLiant DL360 Gen10/ProLiant DL360 Gen10, BIOS U32 09/03/2021 Workqueue: nvme-wq
    nvme_fc_connect_ctrl_work [nvme_fc] RIP: 0010:__wake_up_common+0x4c/0x190 Code: 24 10 4d 85 c9 74 0a 41 f6
    01 04 0f 85 9d 00 00 00 48 8b 43 08 48 83 c3 08 4c 8d 48 e8 49 8d 41 18 48 39 c3 0f 84 f0 00 00 00 <49> 8b
    41 18 89 54 24 08 31 ed 4c 8d 70 e8 45 8b 29 41 f6 c5 04 75 RSP: 0018:ffff95f3e0cb7cd0 EFLAGS: 00010086
    RAX: 0000000000000000 RBX: ffff8b08d3b26328 RCX: 0000000000000000 RDX: 0000000000000001 RSI:
    0000000000000003 RDI: ffff8b08d3b26320 RBP: 0000000000000001 R08: 0000000000000000 R09: ffffffffffffffe8
    R10: 0000000000000000 R11: ffff95f3e0cb7a60 R12: ffff95f3e0cb7d20 R13: 0000000000000003 R14:
    0000000000000000 R15: 0000000000000000 FS: 0000000000000000(0000) GS:ffff8b2fdf6c0000(0000)
    knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000000000000 CR3:
    0000002f1e410002 CR4: 00000000007706e0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
    DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 PKRU: 55555554 Call Trace:
    __wake_up_common_lock+0x7c/0xc0 qla_nvme_ls_req+0x355/0x4c0 [qla2xxx] qla2xxx [0000:12:00.1]-f084:3:
    qlt_free_session_done: se_sess 0000000000000000 / sess ffff8ae1407ca000 from port 21:32:00:02:ac:07:ee:b8
    loop_id 0x02 s_id 01:02:00 logout 1 keep 0 els_logo 0 ? __nvme_fc_send_ls_req+0x260/0x380 [nvme_fc]
    qla2xxx [0000:12:00.1]-207d:3: FCPort 21:32:00:02:ac:07:ee:b8 state transitioned from ONLINE to LOST -
    portid=010200. ? nvme_fc_send_ls_req.constprop.42+0x1a/0x45 [nvme_fc] qla2xxx [0000:12:00.1]-2109:3:
    qla2x00_schedule_rport_del 21320002ac07eeb8. rport ffff8ae598122000 roles 1 ?
    nvme_fc_connect_ctrl_work.cold.63+0x1e3/0xa7d [nvme_fc] qla2xxx [0000:12:00.1]-f084:3:
    qlt_free_session_done: se_sess 0000000000000000 / sess ffff8ae14801e000 from port 21:32:01:02:ad:f7:ee:b8
    loop_id 0x04 s_id 01:02:01 logout 1 keep 0 els_logo 0 ? __switch_to+0x10c/0x450 ?
    process_one_work+0x1a7/0x360 qla2xxx [0000:12:00.1]-207d:3: FCPort 21:32:01:02:ad:f7:ee:b8 state
    transitioned from ONLINE to LOST - portid=010201. ? worker_thread+0x1ce/0x390 ? create_worker+0x1a0/0x1a0
    qla2xxx [0000:12:00.1]-2109:3: qla2x00_schedule_rport_del 21320102adf7eeb8. rport ffff8ae3b2312800 roles
    70 ? kthread+0x10a/0x120 qla2xxx [0000:12:00.1]-2112:3: qla_nvme_unregister_remote_port: unregister
    remoteport on ffff8ae14801e000 21320102adf7eeb8 ? set_kthread_struct+0x40/0x40 qla2xxx
    [0000:12:00.1]-2110:3: remoteport_delete of ffff8ae14801e000 21320102adf7eeb8 completed. ?
    ret_from_fork+0x1f/0x40 qla2xxx [0000:12:00.1]-f086:3: qlt_free_session_done: waiting for sess
    ffff8ae14801e000 logout The system was under memory stress where driver was not able to allocate an SRB to
    carry out error recovery of cable pull. The failure to flush causes upper layer to start modifying
    scsi_cmnd. When the system frees up some memory, the subsequent cable pull trigger another command flush.
    At this point the driver access a null pointer when attempting to DMA unmap the SGL. Add a check to make
    sure commands are flush back on session tear down to prevent the null pointer access. (CVE-2024-26931)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26931");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/01");
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
