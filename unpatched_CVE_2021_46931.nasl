#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224371);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-46931");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-46931");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: Wrap the tx reporter dump
    callback to extract the sq Function mlx5e_tx_reporter_dump_sq() casts its void * argument to struct
    mlx5e_txqsq *, but in TX-timeout-recovery flow the argument is actually of type struct
    mlx5e_tx_timeout_ctx *. mlx5_core 0000:08:00.1 enp8s0f1: TX timeout detected mlx5_core 0000:08:00.1
    enp8s0f1: TX timeout on queue: 1, SQ: 0x11ec, CQ: 0x146d, SQ Cons: 0x0 SQ Prod: 0x1, usecs since last
    trans: 21565000 BUG: stack guard page was hit at 0000000093f1a2de (stack is
    00000000b66ea0dc..000000004d932dae) kernel stack overflow (page fault): 0000 [#1] SMP NOPTI CPU: 5 PID: 95
    Comm: kworker/u20:1 Tainted: G W OE 5.13.0_mlnx #1 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
    BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 Workqueue: mlx5e mlx5e_tx_timeout_work
    [mlx5_core] RIP: 0010:mlx5e_tx_reporter_dump_sq+0xd3/0x180 [mlx5_core] Call Trace:
    mlx5e_tx_reporter_dump+0x43/0x1c0 [mlx5_core] devlink_health_do_dump.part.91+0x71/0xd0
    devlink_health_report+0x157/0x1b0 mlx5e_reporter_tx_timeout+0xb9/0xf0 [mlx5_core] ?
    mlx5e_tx_reporter_err_cqe_recover+0x1d0/0x1d0 [mlx5_core] ? mlx5e_health_queue_dump+0xd0/0xd0 [mlx5_core]
    ? update_load_avg+0x19b/0x550 ? set_next_entity+0x72/0x80 ? pick_next_task_fair+0x227/0x340 ?
    finish_task_switch+0xa2/0x280 mlx5e_tx_timeout_work+0x83/0xb0 [mlx5_core] process_one_work+0x1de/0x3a0
    worker_thread+0x2d/0x3c0 ? process_one_work+0x3a0/0x3a0 kthread+0x115/0x130 ? kthread_park+0x90/0x90
    ret_from_fork+0x1f/0x30 --[ end trace 51ccabea504edaff ]--- RIP: 0010:mlx5e_tx_reporter_dump_sq+0xd3/0x180
    PKRU: 55555554 Kernel panic - not syncing: Fatal exception Kernel Offset: disabled end Kernel panic - not
    syncing: Fatal exception To fix this bug add a wrapper for mlx5e_tx_reporter_dump_sq() which extracts the
    sq from struct mlx5e_tx_timeout_ctx and set it as the TX-timeout-recovery flow dump callback.
    (CVE-2021-46931)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-46931");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
