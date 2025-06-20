#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224458);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47448");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47448");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mptcp: fix possible stall on recvmsg()
    recvmsg() can enter an infinite loop if the caller provides the MSG_WAITALL, the data present in the
    receive queue is not sufficient to fulfill the request, and no more data is received by the peer. When the
    above happens, mptcp_wait_data() will always return with no wait, as the MPTCP_DATA_READY flag checked by
    such function is set and never cleared in such code path. Leveraging the above syzbot was able to trigger
    an RCU stall: rcu: INFO: rcu_preempt self-detected stall on CPU rcu: 0-...!: (10499 ticks this GP)
    idle=0af/1/0x4000000000000000 softirq=10678/10678 fqs=1 (t=10500 jiffies g=13089 q=109) rcu: rcu_preempt
    kthread starved for 10497 jiffies! g13089 f0x0 RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=1 rcu: Unless
    rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior. rcu: RCU grace-period kthread
    stack dump: task:rcu_preempt state:R running task stack:28696 pid: 14 ppid: 2 flags:0x00004000 Call Trace:
    context_switch kernel/sched/core.c:4955 [inline] __schedule+0x940/0x26f0 kernel/sched/core.c:6236
    schedule+0xd3/0x270 kernel/sched/core.c:6315 schedule_timeout+0x14a/0x2a0 kernel/time/timer.c:1881
    rcu_gp_fqs_loop+0x186/0x810 kernel/rcu/tree.c:1955 rcu_gp_kthread+0x1de/0x320 kernel/rcu/tree.c:2128
    kthread+0x405/0x4f0 kernel/kthread.c:327 ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:295 rcu: Stack
    dump where RCU GP kthread last ran: Sending NMI from CPU 0 to CPUs 1: NMI backtrace for cpu 1 CPU: 1 PID:
    8510 Comm: syz-executor827 Not tainted 5.15.0-rc2-next-20210920-syzkaller #0 Hardware name: Google Google
    Compute Engine/Google Compute Engine, BIOS Google 01/01/2011 RIP: 0010:bytes_is_nonzero
    mm/kasan/generic.c:84 [inline] RIP: 0010:memory_is_nonzero mm/kasan/generic.c:102 [inline] RIP:
    0010:memory_is_poisoned_n mm/kasan/generic.c:128 [inline] RIP: 0010:memory_is_poisoned
    mm/kasan/generic.c:159 [inline] RIP: 0010:check_region_inline mm/kasan/generic.c:180 [inline] RIP:
    0010:kasan_check_range+0xc8/0x180 mm/kasan/generic.c:189 Code: 38 00 74 ed 48 8d 50 08 eb 09 48 83 c0 01
    48 39 d0 74 7a 80 38 00 74 f2 48 89 c2 b8 01 00 00 00 48 85 d2 75 56 5b 5d 41 5c c3 <48> 85 d2 74 5e 48 01
    ea eb 09 48 83 c0 01 48 39 d0 74 50 80 38 00 RSP: 0018:ffffc9000cd676c8 EFLAGS: 00000283 RAX:
    ffffed100e9a110e RBX: ffffed100e9a110f RCX: ffffffff88ea062a RDX: 0000000000000001 RSI: 0000000000000008
    RDI: ffff888074d08870 RBP: ffffed100e9a110e R08: 0000000000000001 R09: ffff888074d08877 R10:
    ffffed100e9a110e R11: 0000000000000000 R12: ffff888074d08000 R13: ffff888074d08000 R14: ffff888074d08088
    R15: ffff888074d08000 FS: 0000555556d8e300(0000) GS:ffff8880b9d00000(0000) knlGS:0000000000000000 S: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000020000180 CR3: 0000000068909000 CR4: 00000000001506e0
    DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6:
    00000000fffe0ff0 DR7: 0000000000000400 Call Trace: instrument_atomic_read_write
    include/linux/instrumented.h:101 [inline] test_and_clear_bit include/asm-generic/bitops/instrumented-
    atomic.h:83 [inline] mptcp_release_cb+0x14a/0x210 net/mptcp/protocol.c:3016 release_sock+0xb4/0x1b0
    net/core/sock.c:3204 mptcp_wait_data net/mptcp/protocol.c:1770 [inline] mptcp_recvmsg+0xfd1/0x27b0
    net/mptcp/protocol.c:2080 inet6_recvmsg+0x11b/0x5e0 net/ipv6/af_inet6.c:659 sock_recvmsg_nosec
    net/socket.c:944 [inline] ____sys_recvmsg+0x527/0x600 net/socket.c:2626 ___sys_recvmsg+0x127/0x200
    net/socket.c:2670 do_recvmmsg+0x24d/0x6d0 net/socket.c:2764 __sys_recvmmsg net/socket.c:2843 [inline]
    __do_sys_recvmmsg net/socket.c:2866 [inline] __se_sys_recvmmsg net/socket.c:2859 [inline]
    __x64_sys_recvmmsg+0x20b/0x260 net/socket.c:2859 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
    do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80 entry_SYSCALL_64_after_hwframe+0x44/0xae RIP:
    0033:0x7fc200d2 ---truncated--- (CVE-2021-47448)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47448");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

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
     "bpftool",
     "btrfs-modules-5.10.0-32-alpha-generic-di",
     "cdrom-core-modules-5.10.0-32-alpha-generic-di",
     "hyperv-daemons",
     "kernel-image-5.10.0-32-alpha-generic-di",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bootwrapper-5.10.0-32",
     "linux-config-5.10",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-5.10",
     "linux-headers-5.10.0-32-common",
     "linux-headers-5.10.0-32-common-rt",
     "linux-kbuild-5.10",
     "linux-libc-dev",
     "linux-perf",
     "linux-perf-5.10",
     "linux-source",
     "linux-source-5.10",
     "linux-support-5.10.0-32",
     "loop-modules-5.10.0-32-alpha-generic-di",
     "nic-modules-5.10.0-32-alpha-generic-di",
     "nic-shared-modules-5.10.0-32-alpha-generic-di",
     "nic-wireless-modules-5.10.0-32-alpha-generic-di",
     "pata-modules-5.10.0-32-alpha-generic-di",
     "ppp-modules-5.10.0-32-alpha-generic-di",
     "scsi-core-modules-5.10.0-32-alpha-generic-di",
     "scsi-modules-5.10.0-32-alpha-generic-di",
     "scsi-nic-modules-5.10.0-32-alpha-generic-di",
     "serial-modules-5.10.0-32-alpha-generic-di",
     "usb-serial-modules-5.10.0-32-alpha-generic-di",
     "usbip"
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
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
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
