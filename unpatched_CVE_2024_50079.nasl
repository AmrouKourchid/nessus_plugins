#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230678);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-50079");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-50079");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: io_uring/sqpoll: ensure task state is
    TASK_RUNNING when running task_work When the sqpoll is exiting and cancels pending work items, it may need
    to run task_work. If this happens from within io_uring_cancel_generic(), then it may be under waiting for
    the io_uring_task waitqueue. This results in the below splat from the scheduler, as the ring mutex may be
    attempted grabbed while in a TASK_INTERRUPTIBLE state. Ensure that the task state is set appropriately for
    that, just like what is done for the other cases in io_run_task_work(). do not call blocking ops when
    !TASK_RUNNING; state=1 set at [<0000000029387fd2>] prepare_to_wait+0x88/0x2fc WARNING: CPU: 6 PID: 59939
    at kernel/sched/core.c:8561 __might_sleep+0xf4/0x140 Modules linked in: CPU: 6 UID: 0 PID: 59939 Comm:
    iou-sqp-59938 Not tainted 6.12.0-rc3-00113-g8d020023b155 #7456 Hardware name: linux,dummy-virt (DT)
    pstate: 61400005 (nZCv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=--) pc : __might_sleep+0xf4/0x140 lr :
    __might_sleep+0xf4/0x140 sp : ffff80008c5e7830 x29: ffff80008c5e7830 x28: ffff0000d93088c0 x27:
    ffff60001c2d7230 x26: dfff800000000000 x25: ffff0000e16b9180 x24: ffff80008c5e7a50 x23: 1ffff000118bcf4a
    x22: ffff0000e16b9180 x21: ffff0000e16b9180 x20: 000000000000011b x19: ffff80008310fac0 x18:
    1ffff000118bcd90 x17: 30303c5b20746120 x16: 74657320313d6574 x15: 0720072007200720 x14: 0720072007200720
    x13: 0720072007200720 x12: ffff600036c64f0b x11: 1fffe00036c64f0a x10: ffff600036c64f0a x9 :
    dfff800000000000 x8 : 00009fffc939b0f6 x7 : ffff0001b6327853 x6 : 0000000000000001 x5 : ffff0001b6327850
    x4 : ffff600036c64f0b x3 : ffff8000803c35bc x2 : 0000000000000000 x1 : 0000000000000000 x0 :
    ffff0000e16b9180 Call trace: __might_sleep+0xf4/0x140 mutex_lock+0x84/0x124 io_handle_tw_list+0xf4/0x260
    tctx_task_work_run+0x94/0x340 io_run_task_work+0x1ec/0x3c0 io_uring_cancel_generic+0x364/0x524
    io_sq_thread+0x820/0x124c ret_from_fork+0x10/0x20 (CVE-2024-50079)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50079");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-lowlatency-hwe-6.11",
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
        "os_version": "24.04"
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
