#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229301);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40980");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40980");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drop_monitor: replace spin_lock by
    raw_spin_lock trace_drop_common() is called with preemption disabled, and it acquires a spin_lock. This is
    problematic for RT kernels because spin_locks are sleeping locks in this configuration, which causes the
    following splat: BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48
    in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 449, name: rcuc/47 preempt_count: 1, expected: 0
    RCU nest depth: 2, expected: 2 5 locks held by rcuc/47/449: #0: ff1100086ec30a60
    ((softirq_ctrl.lock)){+.+.}-{2:2}, at: __local_bh_disable_ip+0x105/0x210 #1: ffffffffb394a280
    (rcu_read_lock){....}-{1:2}, at: rt_spin_lock+0xbf/0x130 #2: ffffffffb394a280 (rcu_read_lock){....}-{1:2},
    at: __local_bh_disable_ip+0x11c/0x210 #3: ffffffffb394a160 (rcu_callback){....}-{0:0}, at:
    rcu_do_batch+0x360/0xc70 #4: ff1100086ee07520 (&data->lock){+.+.}-{2:2}, at:
    trace_drop_common.constprop.0+0xb5/0x290 irq event stamp: 139909 hardirqs last enabled at (139908):
    [<ffffffffb1df2b33>] _raw_spin_unlock_irqrestore+0x63/0x80 hardirqs last disabled at (139909):
    [<ffffffffb19bd03d>] trace_drop_common.constprop.0+0x26d/0x290 softirqs last enabled at (139892):
    [<ffffffffb07a1083>] __local_bh_enable_ip+0x103/0x170 softirqs last disabled at (139898):
    [<ffffffffb0909b33>] rcu_cpu_kthread+0x93/0x1f0 Preemption disabled at: [<ffffffffb1de786b>]
    rt_mutex_slowunlock+0xab/0x2e0 CPU: 47 PID: 449 Comm: rcuc/47 Not tainted 6.9.0-rc2-rt1+ #7 Hardware name:
    Dell Inc. PowerEdge R650/0Y2G81, BIOS 1.6.5 04/15/2022 Call Trace: <TASK> dump_stack_lvl+0x8c/0xd0
    dump_stack+0x14/0x20 __might_resched+0x21e/0x2f0 rt_spin_lock+0x5e/0x130 ?
    trace_drop_common.constprop.0+0xb5/0x290 ? skb_queue_purge_reason.part.0+0x1bf/0x230
    trace_drop_common.constprop.0+0xb5/0x290 ? preempt_count_sub+0x1c/0xd0 ?
    _raw_spin_unlock_irqrestore+0x4a/0x80 ? __pfx_trace_drop_common.constprop.0+0x10/0x10 ?
    rt_mutex_slowunlock+0x26a/0x2e0 ? skb_queue_purge_reason.part.0+0x1bf/0x230 ?
    __pfx_rt_mutex_slowunlock+0x10/0x10 ? skb_queue_purge_reason.part.0+0x1bf/0x230
    trace_kfree_skb_hit+0x15/0x20 trace_kfree_skb+0xe9/0x150 kfree_skb_reason+0x7b/0x110
    skb_queue_purge_reason.part.0+0x1bf/0x230 ? __pfx_skb_queue_purge_reason.part.0+0x10/0x10 ?
    mark_lock.part.0+0x8a/0x520 ... trace_drop_common() also disables interrupts, but this is a minor issue
    because we could easily replace it with a local_lock. Replace the spin_lock with raw_spin_lock to avoid
    sleeping in atomic context. (CVE-2024-40980)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/12");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
