#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228930);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42289");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42289");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: qla2xxx: During vport delete
    send async logout explicitly During vport delete, it is observed that during unload we hit a crash because
    of stale entries in outstanding command array. For all these stale I/O entries, eh_abort was issued and
    aborted (fast_fail_io = 2009h) but I/Os could not complete while vport delete is in process of deleting.
    BUG: kernel NULL pointer dereference, address: 000000000000001c #PF: supervisor read access in kernel mode
    #PF: error_code(0x0000) - not-present page PGD 0 P4D 0 Oops: 0000 [#1] PREEMPT SMP NOPTI Workqueue:
    qla2xxx_wq qla_do_work [qla2xxx] RIP: 0010:dma_direct_unmap_sg+0x51/0x1e0 RSP: 0018:ffffa1e1e150fc68
    EFLAGS: 00010046 RAX: 0000000000000000 RBX: 0000000000000021 RCX: 0000000000000001 RDX: 0000000000000021
    RSI: 0000000000000000 RDI: ffff8ce208a7a0d0 RBP: ffff8ce208a7a0d0 R08: 0000000000000000 R09:
    ffff8ce378aac9c8 R10: ffff8ce378aac8a0 R11: ffffa1e1e150f9d8 R12: 0000000000000000 R13: 0000000000000000
    R14: ffff8ce378aac9c8 R15: 0000000000000000 FS: 0000000000000000(0000) GS:ffff8d217f000000(0000)
    knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000000000000001c CR3:
    0000002089acc000 CR4: 0000000000350ee0 Call Trace: <TASK> qla2xxx_qpair_sp_free_dma+0x417/0x4e0 ?
    qla2xxx_qpair_sp_compl+0x10d/0x1a0 ? qla2x00_status_entry+0x768/0x2830 ? newidle_balance+0x2f0/0x430 ?
    dequeue_entity+0x100/0x3c0 ? qla24xx_process_response_queue+0x6a1/0x19e0 ? __schedule+0x2d5/0x1140 ?
    qla_do_work+0x47/0x60 ? process_one_work+0x267/0x440 ? process_one_work+0x440/0x440 ?
    worker_thread+0x2d/0x3d0 ? process_one_work+0x440/0x440 ? kthread+0x156/0x180 ?
    set_kthread_struct+0x50/0x50 ? ret_from_fork+0x22/0x30 </TASK> Send out async logout explicitly for all
    the ports during vport delete. (CVE-2024-42289)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42289");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-azure-fde",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "linux-azure-fde-5.15",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "20.04"
       }
      }
     ]
    }
   ]
  },
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
