#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228219);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26937");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26937");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/i915/gt: Reset queue_priority_hint
    on parking Originally, with strict in order execution, we could complete execution only when the queue was
    empty. Preempt-to-busy allows replacement of an active request that may complete before the preemption is
    processed by HW. If that happens, the request is retired from the queue, but the queue_priority_hint
    remains set, preventing direct submission until after the next CS interrupt is processed. This preempt-to-
    busy race can be triggered by the heartbeat, which will also act as the power-management barrier and upon
    completion allow us to idle the HW. We may process the completion of the heartbeat, and begin parking the
    engine before the CS event that restores the queue_priority_hint, causing us to fail the assertion that it
    is MIN. <3>[ 166.210729] __engine_park:283 GEM_BUG_ON(engine->sched_engine->queue_priority_hint !=
    (-((int)(~0U >> 1)) - 1)) <0>[ 166.210781] Dumping ftrace buffer: <0>[ 166.210795]
    --------------------------------- ... <0>[ 167.302811] drm_fdin-1097 2..s1. 165741070us : trace_ports:
    0000:00:02.0 rcs0: promote { ccid:20 1217:2 prio 0 } <0>[ 167.302861] drm_fdin-1097 2d.s2. 165741072us :
    execlists_submission_tasklet: 0000:00:02.0 rcs0: preempting last=1217:2, prio=0, hint=2147483646 <0>[
    167.302928] drm_fdin-1097 2d.s2. 165741072us : __i915_request_unsubmit: 0000:00:02.0 rcs0: fence 1217:2,
    current 0 <0>[ 167.302992] drm_fdin-1097 2d.s2. 165741073us : __i915_request_submit: 0000:00:02.0 rcs0:
    fence 3:4660, current 4659 <0>[ 167.303044] drm_fdin-1097 2d.s1. 165741076us :
    execlists_submission_tasklet: 0000:00:02.0 rcs0: context:3 schedule-in, ccid:40 <0>[ 167.303095]
    drm_fdin-1097 2d.s1. 165741077us : trace_ports: 0000:00:02.0 rcs0: submit { ccid:40 3:4660* prio
    2147483646 } <0>[ 167.303159] kworker/-89 11..... 165741139us : i915_request_retire.part.0: 0000:00:02.0
    rcs0: fence c90:2, current 2 <0>[ 167.303208] kworker/-89 11..... 165741148us : __intel_context_do_unpin:
    0000:00:02.0 rcs0: context:c90 unpin <0>[ 167.303272] kworker/-89 11..... 165741159us :
    i915_request_retire.part.0: 0000:00:02.0 rcs0: fence 1217:2, current 2 <0>[ 167.303321] kworker/-89
    11..... 165741166us : __intel_context_do_unpin: 0000:00:02.0 rcs0: context:1217 unpin <0>[ 167.303384]
    kworker/-89 11..... 165741170us : i915_request_retire.part.0: 0000:00:02.0 rcs0: fence 3:4660, current
    4660 <0>[ 167.303434] kworker/-89 11d..1. 165741172us : __intel_context_retire: 0000:00:02.0 rcs0:
    context:1216 retire runtime: { total:56028ns, avg:56028ns } <0>[ 167.303484] kworker/-89 11.....
    165741198us : __engine_park: 0000:00:02.0 rcs0: parked <0>[ 167.303534] <idle>-0 5d.H3. 165741207us :
    execlists_irq_handler: 0000:00:02.0 rcs0: semaphore yield: 00000040 <0>[ 167.303583] kworker/-89 11.....
    165741397us : __intel_context_retire: 0000:00:02.0 rcs0: context:1217 retire runtime: { total:325575ns,
    avg:0ns } <0>[ 167.303756] kworker/-89 11..... 165741777us : __intel_context_retire: 0000:00:02.0 rcs0:
    context:c90 retire runtime: { total:0ns, avg:0ns } <0>[ 167.303806] kworker/-89 11..... 165742017us :
    __engine_park: __engine_park:283 GEM_BUG_ON(engine->sched_engine->queue_priority_hint != (-((int)(~0U >>
    1)) - 1)) <0>[ 167.303811] --------------------------------- <4>[ 167.304722] ------------[ cut here
    ]------------ <2>[ 167.304725] kernel BUG at drivers/gpu/drm/i915/gt/intel_engine_pm.c:283! <4>[
    167.304731] invalid opcode: 0000 [#1] PREEMPT SMP NOPTI <4>[ 167.304734] CPU: 11 PID: 89 Comm:
    kworker/11:1 Tainted: G W 6.8.0-rc2-CI_DRM_14193-gc655e0fd2804+ #1 <4>[ 167.304736] Hardware name: Intel
    Corporation Rocket Lake Client Platform/RocketLake S UDIMM 6L RVP, BIOS RKLSFWI1.R00.3173.A03.2204210138
    04/21/2022 <4>[ 167.304738] Workqueue: i915-unordered retire_work_handler [i915] <4>[ 16 ---truncated---
    (CVE-2024-26937)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26937");

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
