#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224427);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-46983");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-46983");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: nvmet-rdma: Fix NULL deref when SEND
    is completed with error When running some traffic and taking down the link on peer, a retry counter
    exceeded error is received. This leads to nvmet_rdma_error_comp which tried accessing the cq_context to
    obtain the queue. The cq_context is no longer valid after the fix to use shared CQ mechanism and should be
    obtained similar to how it is obtained in other functions from the wc->qp. [ 905.786331] nvmet_rdma: SEND
    for CQE 0x00000000e3337f90 failed with status transport retry counter exceeded (12). [ 905.832048] BUG:
    unable to handle kernel NULL pointer dereference at 0000000000000048 [ 905.839919] PGD 0 P4D 0 [
    905.842464] Oops: 0000 1 SMP NOPTI [ 905.846144] CPU: 13 PID: 1557 Comm: kworker/13:1H Kdump: loaded
    Tainted: G OE --------- - - 4.18.0-304.el8.x86_64 #1 [ 905.872135] RIP:
    0010:nvmet_rdma_error_comp+0x5/0x1b [nvmet_rdma] [ 905.878259] Code: 19 4f c0 e8 89 b3 a5 f6 e9 5b e0 ff
    ff 0f b7 75 14 4c 89 ea 48 c7 c7 08 1a 4f c0 e8 71 b3 a5 f6 e9 4b e0 ff ff 0f 1f 44 00 00 <48> 8b 47 48 48
    85 c0 74 08 48 89 c7 e9 98 bf 49 00 e9 c3 e3 ff ff [ 905.897135] RSP: 0018:ffffab601c45fe28 EFLAGS:
    00010246 [ 905.902387] RAX: 0000000000000065 RBX: ffff9e729ea2f800 RCX: 0000000000000000 [ 905.909558]
    RDX: 0000000000000000 RSI: ffff9e72df9567c8 RDI: 0000000000000000 [ 905.916731] RBP: ffff9e729ea2b400 R08:
    000000000000074d R09: 0000000000000074 [ 905.923903] R10: 0000000000000000 R11: ffffab601c45fcc0 R12:
    0000000000000010 [ 905.931074] R13: 0000000000000000 R14: 0000000000000010 R15: ffff9e729ea2f400 [
    905.938247] FS: 0000000000000000(0000) GS:ffff9e72df940000(0000) knlGS:0000000000000000 [ 905.938249] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 905.950067] nvmet_rdma: SEND for CQE 0x00000000c7356cca
    failed with status transport retry counter exceeded (12). [ 905.961855] CR2: 0000000000000048 CR3:
    000000678d010004 CR4: 00000000007706e0 [ 905.961855] DR0: 0000000000000000 DR1: 0000000000000000 DR2:
    0000000000000000 [ 905.961856] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [
    905.961857] PKRU: 55555554 [ 906.010315] Call Trace: [ 906.012778] __ib_process_cq+0x89/0x170 [ib_core] [
    906.017509] ib_cq_poll_work+0x26/0x80 [ib_core] [ 906.022152] process_one_work+0x1a7/0x360 [ 906.026182] ?
    create_worker+0x1a0/0x1a0 [ 906.030123] worker_thread+0x30/0x390 [ 906.033802] ? create_worker+0x1a0/0x1a0
    [ 906.037744] kthread+0x116/0x130 [ 906.040988] ? kthread_flush_work_fn+0x10/0x10 [ 906.045456]
    ret_from_fork+0x1f/0x40 (CVE-2021-46983)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-46983");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
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
