#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224369);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47185");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47185");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tty: tty_buffer: Fix the softlockup
    issue in flush_to_ldisc When running ltp testcase(ltp/testcases/kernel/pty/pty04.c) with arm64, there is a
    soft lockup, which look like this one: Workqueue: events_unbound flush_to_ldisc Call trace:
    dump_backtrace+0x0/0x1ec show_stack+0x24/0x30 dump_stack+0xd0/0x128 panic+0x15c/0x374
    watchdog_timer_fn+0x2b8/0x304 __run_hrtimer+0x88/0x2c0 __hrtimer_run_queues+0xa4/0x120
    hrtimer_interrupt+0xfc/0x270 arch_timer_handler_phys+0x40/0x50 handle_percpu_devid_irq+0x94/0x220
    __handle_domain_irq+0x88/0xf0 gic_handle_irq+0x84/0xfc el1_irq+0xc8/0x180 slip_unesc+0x80/0x214 [slip]
    tty_ldisc_receive_buf+0x64/0x80 tty_port_default_receive_buf+0x50/0x90 flush_to_ldisc+0xbc/0x110
    process_one_work+0x1d4/0x4b0 worker_thread+0x180/0x430 kthread+0x11c/0x120 In the testcase pty04, The
    first process call the write syscall to send data to the pty master. At the same time, the workqueue will
    do the flush_to_ldisc to pop data in a loop until there is no more data left. When the sender and
    workqueue running in different core, the sender sends data fastly in full time which will result in
    workqueue doing work in loop for a long time and occuring softlockup in flush_to_ldisc with kernel
    configured without preempt. So I add need_resched check and cond_resched in the flush_to_ldisc loop to
    avoid it. (CVE-2021-47185)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47185");

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
