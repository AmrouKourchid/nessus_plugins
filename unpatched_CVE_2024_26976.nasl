#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227645);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26976");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26976");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: Always flush async #PF workqueue
    when vCPU is being destroyed Always flush the per-vCPU async #PF workqueue when a vCPU is clearing its
    completion queue, e.g. when a VM and all its vCPUs is being destroyed. KVM must ensure that none of its
    workqueue callbacks is running when the last reference to the KVM _module_ is put. Gifting a reference to
    the associated VM prevents the workqueue callback from dereferencing freed vCPU/VM memory, but does not
    prevent the KVM module from being unloaded before the callback completes. Drop the misguided VM refcount
    gifting, as calling kvm_put_kvm() from async_pf_execute() if kvm_put_kvm() flushes the async #PF workqueue
    will result in deadlock. async_pf_execute() can't return until kvm_put_kvm() finishes, and kvm_put_kvm()
    can't return until async_pf_execute() finishes: WARNING: CPU: 8 PID: 251 at virt/kvm/kvm_main.c:1435
    kvm_put_kvm+0x2d/0x320 [kvm] Modules linked in: vhost_net vhost vhost_iotlb tap kvm_intel kvm irqbypass
    CPU: 8 PID: 251 Comm: kworker/8:1 Tainted: G W 6.6.0-rc1-e7af8d17224a-x86/gmem-vm #119 Hardware name: QEMU
    Standard PC (Q35 + ICH9, 2009), BIOS 0.0.0 02/06/2015 Workqueue: events async_pf_execute [kvm] RIP:
    0010:kvm_put_kvm+0x2d/0x320 [kvm] Call Trace: <TASK> async_pf_execute+0x198/0x260 [kvm]
    process_one_work+0x145/0x2d0 worker_thread+0x27e/0x3a0 kthread+0xba/0xe0 ret_from_fork+0x2d/0x50
    ret_from_fork_asm+0x11/0x20 </TASK> ---[ end trace 0000000000000000 ]--- INFO: task kworker/8:1:251
    blocked for more than 120 seconds. Tainted: G W 6.6.0-rc1-e7af8d17224a-x86/gmem-vm #119 echo 0 >
    /proc/sys/kernel/hung_task_timeout_secs disables this message. task:kworker/8:1 state:D stack:0 pid:251
    ppid:2 flags:0x00004000 Workqueue: events async_pf_execute [kvm] Call Trace: <TASK> __schedule+0x33f/0xa40
    schedule+0x53/0xc0 schedule_timeout+0x12a/0x140 __wait_for_common+0x8d/0x1d0
    __flush_work.isra.0+0x19f/0x2c0 kvm_clear_async_pf_completion_queue+0x129/0x190 [kvm]
    kvm_arch_destroy_vm+0x78/0x1b0 [kvm] kvm_put_kvm+0x1c1/0x320 [kvm] async_pf_execute+0x198/0x260 [kvm]
    process_one_work+0x145/0x2d0 worker_thread+0x27e/0x3a0 kthread+0xba/0xe0 ret_from_fork+0x2d/0x50
    ret_from_fork_asm+0x11/0x20 </TASK> If kvm_clear_async_pf_completion_queue() actually flushes the
    workqueue, then there's no need to gift async_pf_execute() a reference because all invocations of
    async_pf_execute() will be forced to complete before the vCPU and its VM are destroyed/freed. And that in
    turn fixes the module unloading bug as __fput() won't do module_put() on the last vCPU reference until the
    vCPU has been freed, e.g. if closing the vCPU file also puts the last reference to the KVM module. Note
    that kvm_check_async_pf_completion() may also take the work item off the completion queue and so also
    needs to flush the work queue, as the work will not be seen by kvm_clear_async_pf_completion_queue().
    Waiting on the workqueue could theoretically delay a vCPU due to waiting for the work to complete, but
    that's a very, very small chance, and likely a very small delay. kvm_arch_async_page_present_queued()
    unconditionally makes a new request, i.e. will effectively delay entering the guest, so the remaining work
    is really just: trace_kvm_async_pf_completed(addr, cr2_or_gpa); __kvm_vcpu_wake_up(vcpu); mmput(mm); and
    mmput() can't drop the last reference to the page tables if the vCPU is still alive, i.e. the vCPU won't
    get stuck tearing down page tables. Add a helper to do the flushing, specifically to deal with wakeup
    all work items, as they aren't actually work items, i.e. are never placed in a workqueue. Trying to flush
    a bogus workqueue entry rightly makes __flush_work() complain (kudos to whoever added that sanity check).
    Note, commit 5f6de5cbebee (KVM: Prevent module exit until al ---truncated--- (CVE-2024-26976)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26976");

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
