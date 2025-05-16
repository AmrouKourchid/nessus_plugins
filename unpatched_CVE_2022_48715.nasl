#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225607);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48715");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48715");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: bnx2fc: Make bnx2fc_recv_frame()
    mp safe Running tests with a debug kernel shows that bnx2fc_recv_frame() is modifying the per_cpu lport
    stats counters in a non-mpsafe way. Just boot a debug kernel and run the bnx2fc driver with the hardware
    enabled. [ 1391.699147] BUG: using smp_processor_id() in preemptible [00000000] code: bnx2fc_ [
    1391.699160] caller is bnx2fc_recv_frame+0xbf9/0x1760 [bnx2fc] [ 1391.699174] CPU: 2 PID: 4355 Comm:
    bnx2fc_l2_threa Kdump: loaded Tainted: G B [ 1391.699180] Hardware name: HP ProLiant DL120 G7, BIOS J01
    07/01/2013 [ 1391.699183] Call Trace: [ 1391.699188] dump_stack_lvl+0x57/0x7d [ 1391.699198]
    check_preemption_disabled+0xc8/0xd0 [ 1391.699205] bnx2fc_recv_frame+0xbf9/0x1760 [bnx2fc] [ 1391.699215]
    ? do_raw_spin_trylock+0xb5/0x180 [ 1391.699221] ? bnx2fc_npiv_create_vports.isra.0+0x4e0/0x4e0 [bnx2fc] [
    1391.699229] ? bnx2fc_l2_rcv_thread+0xb7/0x3a0 [bnx2fc] [ 1391.699240] bnx2fc_l2_rcv_thread+0x1af/0x3a0
    [bnx2fc] [ 1391.699250] ? bnx2fc_ulp_init+0xc0/0xc0 [bnx2fc] [ 1391.699258] kthread+0x364/0x420 [
    1391.699263] ? _raw_spin_unlock_irq+0x24/0x50 [ 1391.699268] ? set_kthread_struct+0x100/0x100 [
    1391.699273] ret_from_fork+0x22/0x30 Restore the old get_cpu/put_cpu code with some modifications to
    reduce the size of the critical section. (CVE-2022-48715)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/20");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
