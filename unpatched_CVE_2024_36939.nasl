#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229040);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36939");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36939");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: nfs: Handle error of
    rpc_proc_register() in nfs_net_init(). syzkaller reported a warning [0] triggered while destroying
    immature netns. rpc_proc_register() was called in init_nfs_fs(), but its error has been ignored since at
    least the initial commit 1da177e4c3f4 (Linux-2.6.12-rc2). Recently, commit d47151b79e32 (nfs: expose
    /proc/net/sunrpc/nfs in net namespaces) converted the procfs to per-netns and made the problem more
    visible. Even when rpc_proc_register() fails, nfs_net_init() could succeed, and thus nfs_net_exit() will
    be called while destroying the netns. Then, remove_proc_entry() will be called for non-existing proc
    directory and trigger the warning below. Let's handle the error of rpc_proc_register() properly in
    nfs_net_init(). [0]: name 'nfs' WARNING: CPU: 1 PID: 1710 at fs/proc/generic.c:711
    remove_proc_entry+0x1bb/0x2d0 fs/proc/generic.c:711 Modules linked in: CPU: 1 PID: 1710 Comm: syz-
    executor.2 Not tainted 6.8.0-12822-gcd51db110a7e #12 Hardware name: QEMU Standard PC (i440FX + PIIX,
    1996), BIOS rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014 RIP:
    0010:remove_proc_entry+0x1bb/0x2d0 fs/proc/generic.c:711 Code: 41 5d 41 5e c3 e8 85 09 b5 ff 48 c7 c7 88
    58 64 86 e8 09 0e 71 02 e8 74 09 b5 ff 4c 89 e6 48 c7 c7 de 1b 80 84 e8 c5 ad 97 ff <0f> 0b eb b1 e8 5c 09
    b5 ff 48 c7 c7 88 58 64 86 e8 e0 0d 71 02 eb RSP: 0018:ffffc9000c6d7ce0 EFLAGS: 00010286 RAX:
    0000000000000000 RBX: ffff8880422b8b00 RCX: ffffffff8110503c RDX: ffff888030652f00 RSI: ffffffff81105045
    RDI: 0000000000000001 RBP: 0000000000000000 R08: 0000000000000001 R09: 0000000000000000 R10:
    0000000000000001 R11: ffffffff81bb62cb R12: ffffffff84807ffc R13: ffff88804ad6fcc0 R14: ffffffff84807ffc
    R15: ffffffff85741ff8 FS: 00007f30cfba8640(0000) GS:ffff88807dd00000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007ff51afe8000 CR3: 000000005a60a005 CR4: 0000000000770ef0
    DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6:
    00000000fffe0ff0 DR7: 0000000000000400 PKRU: 55555554 Call Trace: <TASK> rpc_proc_unregister+0x64/0x70
    net/sunrpc/stats.c:310 nfs_net_exit+0x1c/0x30 fs/nfs/inode.c:2438 ops_exit_list+0x62/0xb0
    net/core/net_namespace.c:170 setup_net+0x46c/0x660 net/core/net_namespace.c:372 copy_net_ns+0x244/0x590
    net/core/net_namespace.c:505 create_new_namespaces+0x2ed/0x770 kernel/nsproxy.c:110
    unshare_nsproxy_namespaces+0xae/0x160 kernel/nsproxy.c:228 ksys_unshare+0x342/0x760 kernel/fork.c:3322
    __do_sys_unshare kernel/fork.c:3393 [inline] __se_sys_unshare kernel/fork.c:3391 [inline]
    __x64_sys_unshare+0x1f/0x30 kernel/fork.c:3391 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0x4f/0x110 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x46/0x4e RIP:
    0033:0x7f30d0febe5d Code: ff c3 66 2e 0f 1f 84 00 00 00 00 00 90 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48
    89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 73 9f 1b 00 f7 d8 64 89
    01 48 RSP: 002b:00007f30cfba7cc8 EFLAGS: 00000246 ORIG_RAX: 0000000000000110 RAX: ffffffffffffffda RBX:
    00000000004bbf80 RCX: 00007f30d0febe5d RDX: 0000000000000000 RSI: 0000000000000000 RDI: 000000006c020600
    RBP: 00000000004bbf80 R08: 0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11:
    0000000000000246 R12: 0000000000000002 R13: 000000000000000b R14: 00007f30d104c530 R15: 0000000000000000
    </TASK> (CVE-2024-36939)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36939");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/23");
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
