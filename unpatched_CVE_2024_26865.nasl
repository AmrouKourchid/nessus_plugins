#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228047);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26865");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26865");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: rds: tcp: Fix use-after-free of net in
    reqsk_timer_handler(). syzkaller reported a warning of netns tracker [0] followed by KASAN splat [1] and
    another ref tracker warning [1]. syzkaller could not find a repro, but in the log, the only suspicious
    sequence was as follows: 18:26:22 executing program 1: r0 = socket$inet6_mptcp(0xa, 0x1, 0x106) ...
    connect$inet6(r0, &(0x7f0000000080)={0xa, 0x4001, 0x0, @loopback}, 0x1c) (async) The notable thing here is
    0x4001 in connect(), which is RDS_TCP_PORT. So, the scenario would be: 1. unshare(CLONE_NEWNET) creates a
    per netns tcp listener in rds_tcp_listen_init(). 2. syz-executor connect()s to it and creates a reqsk. 3.
    syz-executor exit()s immediately. 4. netns is dismantled. [0] 5. reqsk timer is fired, and UAF happens
    while freeing reqsk. [1] 6. listener is freed after RCU grace period. [2] Basically, reqsk assumes that
    the listener guarantees netns safety until all reqsk timers are expired by holding the listener's
    refcount. However, this was not the case for kernel sockets. Commit 740ea3c4a0b2 (tcp: Clean up kernel
    listener's reqsk in inet_twsk_purge()) fixed this issue only for per-netns ehash. Let's apply the same
    fix for the global ehash. [0]: ref_tracker: net notrefcnt@0000000065449cc3 has 1/1 users at sk_alloc
    (./include/net/net_namespace.h:337 net/core/sock.c:2146) inet6_create (net/ipv6/af_inet6.c:192
    net/ipv6/af_inet6.c:119) __sock_create (net/socket.c:1572) rds_tcp_listen_init (net/rds/tcp_listen.c:279)
    rds_tcp_init_net (net/rds/tcp.c:577) ops_init (net/core/net_namespace.c:137) setup_net
    (net/core/net_namespace.c:340) copy_net_ns (net/core/net_namespace.c:497) create_new_namespaces
    (kernel/nsproxy.c:110) unshare_nsproxy_namespaces (kernel/nsproxy.c:228 (discriminator 4)) ksys_unshare
    (kernel/fork.c:3429) __x64_sys_unshare (kernel/fork.c:3496) do_syscall_64 (arch/x86/entry/common.c:52
    arch/x86/entry/common.c:83) entry_SYSCALL_64_after_hwframe (arch/x86/entry/entry_64.S:129) ... WARNING:
    CPU: 0 PID: 27 at lib/ref_tracker.c:179 ref_tracker_dir_exit (lib/ref_tracker.c:179) [1]: BUG: KASAN:
    slab-use-after-free in inet_csk_reqsk_queue_drop (./include/net/inet_hashtables.h:180
    net/ipv4/inet_connection_sock.c:952 net/ipv4/inet_connection_sock.c:966) Read of size 8 at addr
    ffff88801b370400 by task swapper/0/0 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
    rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014 Call Trace: <IRQ> dump_stack_lvl
    (lib/dump_stack.c:107 (discriminator 1)) print_report (mm/kasan/report.c:378 mm/kasan/report.c:488)
    kasan_report (mm/kasan/report.c:603) inet_csk_reqsk_queue_drop (./include/net/inet_hashtables.h:180
    net/ipv4/inet_connection_sock.c:952 net/ipv4/inet_connection_sock.c:966) reqsk_timer_handler
    (net/ipv4/inet_connection_sock.c:979 net/ipv4/inet_connection_sock.c:1092) call_timer_fn
    (./arch/x86/include/asm/jump_label.h:27 ./include/linux/jump_label.h:207
    ./include/trace/events/timer.h:127 kernel/time/timer.c:1701) __run_timers.part.0 (kernel/time/timer.c:1752
    kernel/time/timer.c:2038) run_timer_softirq (kernel/time/timer.c:2053) __do_softirq
    (./arch/x86/include/asm/jump_label.h:27 ./include/linux/jump_label.h:207 ./include/trace/events/irq.h:142
    kernel/softirq.c:554) irq_exit_rcu (kernel/softirq.c:427 kernel/softirq.c:632 kernel/softirq.c:644)
    sysvec_apic_timer_interrupt (arch/x86/kernel/apic/apic.c:1076 (discriminator 14)) </IRQ> Allocated by task
    258 on cpu 0 at 83.612050s: kasan_save_stack (mm/kasan/common.c:48) kasan_save_track
    (mm/kasan/common.c:68) __kasan_slab_alloc (mm/kasan/common.c:343) kmem_cache_alloc (mm/slub.c:3813
    mm/slub.c:3860 mm/slub.c:3867) copy_net_ns (./include/linux/slab.h:701 net/core/net_namespace.c:421
    net/core/net_namespace.c:480) create_new_namespaces (kernel/nsproxy.c:110) unshare_nsproxy_name
    ---truncated--- (CVE-2024-26865)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26865");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
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
