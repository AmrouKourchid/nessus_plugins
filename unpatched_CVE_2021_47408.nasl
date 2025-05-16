#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224350);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47408");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47408");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: conntrack: serialize hash
    resizes and cleanups Syzbot was able to trigger the following warning [1] No repro found by syzbot yet but
    I was able to trigger similar issue by having 2 scripts running in parallel, changing conntrack hash
    sizes, and: for j in `seq 1 1000` ; do unshare -n /bin/true >/dev/null ; done It would take more than 5
    minutes for net_namespace structures to be cleaned up. This is because nf_ct_iterate_cleanup() has to
    restart everytime a resize happened. By adding a mutex, we can serialize hash resizes and cleanups and
    also make get_next_corpse() faster by skipping over empty buckets. Even without resizes in the picture,
    this patch considerably speeds up network namespace dismantles. [1] INFO: task syz-executor.0:8312 can't
    die for more than 144 seconds. task:syz-executor.0 state:R running task stack:25672 pid: 8312 ppid: 6573
    flags:0x00004006 Call Trace: context_switch kernel/sched/core.c:4955 [inline] __schedule+0x940/0x26f0
    kernel/sched/core.c:6236 preempt_schedule_common+0x45/0xc0 kernel/sched/core.c:6408
    preempt_schedule_thunk+0x16/0x18 arch/x86/entry/thunk_64.S:35 __local_bh_enable_ip+0x109/0x120
    kernel/softirq.c:390 local_bh_enable include/linux/bottom_half.h:32 [inline] get_next_corpse
    net/netfilter/nf_conntrack_core.c:2252 [inline] nf_ct_iterate_cleanup+0x15a/0x450
    net/netfilter/nf_conntrack_core.c:2275 nf_conntrack_cleanup_net_list+0x14c/0x4f0
    net/netfilter/nf_conntrack_core.c:2469 ops_exit_list+0x10d/0x160 net/core/net_namespace.c:171
    setup_net+0x639/0xa30 net/core/net_namespace.c:349 copy_net_ns+0x319/0x760 net/core/net_namespace.c:470
    create_new_namespaces+0x3f6/0xb20 kernel/nsproxy.c:110 unshare_nsproxy_namespaces+0xc1/0x1f0
    kernel/nsproxy.c:226 ksys_unshare+0x445/0x920 kernel/fork.c:3128 __do_sys_unshare kernel/fork.c:3202
    [inline] __se_sys_unshare kernel/fork.c:3200 [inline] __x64_sys_unshare+0x2d/0x40 kernel/fork.c:3200
    do_syscall_x64 arch/x86/entry/common.c:50 [inline] do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x44/0xae RIP: 0033:0x7f63da68e739 RSP: 002b:00007f63d7c05188 EFLAGS:
    00000246 ORIG_RAX: 0000000000000110 RAX: ffffffffffffffda RBX: 00007f63da792f80 RCX: 00007f63da68e739 RDX:
    0000000000000000 RSI: 0000000000000000 RDI: 0000000040000000 RBP: 00007f63da6e8cc4 R08: 0000000000000000
    R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 00007f63da792f80 R13:
    00007fff50b75d3f R14: 00007f63d7c05300 R15: 0000000000022000 Showing all locks held in the system: 1 lock
    held by khungtaskd/27: #0: ffffffff8b980020 (rcu_read_lock){....}-{1:2}, at:
    debug_show_all_locks+0x53/0x260 kernel/locking/lockdep.c:6446 2 locks held by kworker/u4:2/153: #0:
    ffff888010c69138 ((wq_completion)events_unbound){+.+.}-{0:0}, at: arch_atomic64_set
    arch/x86/include/asm/atomic64_64.h:34 [inline] #0: ffff888010c69138
    ((wq_completion)events_unbound){+.+.}-{0:0}, at: arch_atomic_long_set include/linux/atomic/atomic-
    long.h:41 [inline] #0: ffff888010c69138 ((wq_completion)events_unbound){+.+.}-{0:0}, at: atomic_long_set
    include/linux/atomic/atomic-instrumented.h:1198 [inline] #0: ffff888010c69138
    ((wq_completion)events_unbound){+.+.}-{0:0}, at: set_work_data kernel/workqueue.c:634 [inline] #0:
    ffff888010c69138 ((wq_completion)events_unbound){+.+.}-{0:0}, at: set_work_pool_and_clear_pending
    kernel/workqueue.c:661 [inline] #0: ffff888010c69138 ((wq_completion)events_unbound){+.+.}-{0:0}, at:
    process_one_work+0x896/0x1690 kernel/workqueue.c:2268 #1: ffffc9000140fdb0
    ((kfence_timer).work){+.+.}-{0:0}, at: process_one_work+0x8ca/0x1690 kernel/workqueue.c:2272 1 lock held
    by systemd-udevd/2970: 1 lock held by in:imklog/6258: #0: ffff88807f970ff0 (&f->f_pos_lock){+.+.}-{3:3},
    at: __fdget_pos+0xe9/0x100 fs/file.c:990 3 locks held by kworker/1:6/8158: 1 lock held by syz-
    executor.0/8312: 2 locks held by kworker/u4:13/9320: 1 lock held by ---truncated--- (CVE-2021-47408)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47408");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

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
    "name": [
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
     "linux-azure-cloud-tools-5.4.0-1010",
     "linux-azure-fips",
     "linux-azure-headers-5.4.0-1010",
     "linux-azure-tools-5.4.0-1010",
     "linux-bluefield",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-buildinfo-5.4.0-1009-aws",
     "linux-buildinfo-5.4.0-1009-gcp",
     "linux-buildinfo-5.4.0-1009-kvm",
     "linux-buildinfo-5.4.0-1009-oracle",
     "linux-buildinfo-5.4.0-1010-azure",
     "linux-buildinfo-5.4.0-26-generic",
     "linux-buildinfo-5.4.0-26-generic-lpae",
     "linux-cloud-tools-5.4.0-1009-aws",
     "linux-cloud-tools-5.4.0-1009-kvm",
     "linux-cloud-tools-5.4.0-1009-oracle",
     "linux-cloud-tools-5.4.0-1010-azure",
     "linux-cloud-tools-5.4.0-26",
     "linux-cloud-tools-5.4.0-26-generic",
     "linux-cloud-tools-5.4.0-26-generic-lpae",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-fips",
     "linux-gcp-fips",
     "linux-gcp-headers-5.4.0-1009",
     "linux-gcp-tools-5.4.0-1009",
     "linux-headers-5.4.0-1008-raspi",
     "linux-headers-5.4.0-1009-aws",
     "linux-headers-5.4.0-1009-gcp",
     "linux-headers-5.4.0-1009-kvm",
     "linux-headers-5.4.0-1009-oracle",
     "linux-headers-5.4.0-1010-azure",
     "linux-headers-5.4.0-26",
     "linux-headers-5.4.0-26-generic",
     "linux-headers-5.4.0-26-generic-lpae",
     "linux-ibm",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-image-5.4.0-1009-aws",
     "linux-image-5.4.0-1009-aws-dbgsym",
     "linux-image-5.4.0-1009-kvm",
     "linux-image-5.4.0-1009-kvm-dbgsym",
     "linux-image-unsigned-5.4.0-1009-gcp",
     "linux-image-unsigned-5.4.0-1009-gcp-dbgsym",
     "linux-image-unsigned-5.4.0-1009-oracle",
     "linux-image-unsigned-5.4.0-1009-oracle-dbgsym",
     "linux-image-unsigned-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic",
     "linux-image-unsigned-5.4.0-26-generic-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic-lpae",
     "linux-image-unsigned-5.4.0-26-generic-lpae-dbgsym",
     "linux-image-unsigned-5.4.0-26-lowlatency",
     "linux-iot",
     "linux-kvm-cloud-tools-5.4.0-1009",
     "linux-kvm-headers-5.4.0-1009",
     "linux-kvm-tools-5.4.0-1009",
     "linux-libc-dev",
     "linux-modules-5.4.0-1008-raspi",
     "linux-modules-5.4.0-1009-aws",
     "linux-modules-5.4.0-1009-gcp",
     "linux-modules-5.4.0-1009-kvm",
     "linux-modules-5.4.0-1009-oracle",
     "linux-modules-5.4.0-1010-azure",
     "linux-modules-5.4.0-26-generic",
     "linux-modules-5.4.0-26-generic-lpae",
     "linux-modules-5.4.0-26-lowlatency",
     "linux-modules-extra-5.4.0-1009-aws",
     "linux-modules-extra-5.4.0-1009-gcp",
     "linux-modules-extra-5.4.0-1009-kvm",
     "linux-modules-extra-5.4.0-1009-oracle",
     "linux-modules-extra-5.4.0-1010-azure",
     "linux-modules-extra-5.4.0-26-generic",
     "linux-modules-extra-5.4.0-26-generic-lpae",
     "linux-modules-extra-5.4.0-26-lowlatency",
     "linux-oracle-headers-5.4.0-1009",
     "linux-oracle-tools-5.4.0-1009",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-source-5.4.0",
     "linux-tools-5.4.0-1008-raspi",
     "linux-tools-5.4.0-1009-aws",
     "linux-tools-5.4.0-1009-gcp",
     "linux-tools-5.4.0-1009-kvm",
     "linux-tools-5.4.0-1009-oracle",
     "linux-tools-5.4.0-1010-azure",
     "linux-tools-5.4.0-26",
     "linux-tools-5.4.0-26-generic",
     "linux-tools-5.4.0-26-generic-lpae",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-kvm",
     "linux-xilinx-zynqmp"
    ],
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
