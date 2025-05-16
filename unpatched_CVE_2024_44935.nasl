#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228485);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-44935");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-44935");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: sctp: Fix null-ptr-deref in
    reuseport_add_sock(). syzbot reported a null-ptr-deref while accessing sk2->sk_reuseport_cb in
    reuseport_add_sock(). [0] The repro first creates a listener with SO_REUSEPORT. Then, it creates another
    listener on the same port and concurrently closes the first listener. The second listen() calls
    reuseport_add_sock() with the first listener as sk2, where sk2->sk_reuseport_cb is not expected to be
    cleared concurrently, but the close() does clear it by reuseport_detach_sock(). The problem is SCTP does
    not properly synchronise reuseport_alloc(), reuseport_add_sock(), and reuseport_detach_sock(). The caller
    of reuseport_alloc() and reuseport_{add,detach}_sock() must provide synchronisation for sockets that are
    classified into the same reuseport group. Otherwise, such sockets form multiple identical reuseport
    groups, and all groups except one would be silently dead. 1. Two sockets call listen() concurrently 2. No
    socket in the same group found in sctp_ep_hashtable[] 3. Two sockets call reuseport_alloc() and form two
    reuseport groups 4. Only one group hit first in __sctp_rcv_lookup_endpoint() receives incoming packets
    Also, the reported null-ptr-deref could occur. TCP/UDP guarantees that would not happen by holding the
    hash bucket lock. Let's apply the locking strategy to __sctp_hash_endpoint() and __sctp_unhash_endpoint().
    [0]: Oops: general protection fault, probably for non-canonical address 0xdffffc0000000002: 0000 [#1]
    PREEMPT SMP KASAN PTI KASAN: null-ptr-deref in range [0x0000000000000010-0x0000000000000017] CPU: 1 UID: 0
    PID: 10230 Comm: syz-executor119 Not tainted 6.10.0-syzkaller-12585-g301927d2d2eb #0 Hardware name: Google
    Google Compute Engine/Google Compute Engine, BIOS Google 06/27/2024 RIP:
    0010:reuseport_add_sock+0x27e/0x5e0 net/core/sock_reuseport.c:350 Code: 00 0f b7 5d 00 bf 01 00 00 00 89
    de e8 1b a4 ff f7 83 fb 01 0f 85 a3 01 00 00 e8 6d a0 ff f7 49 8d 7e 12 48 89 f8 48 c1 e8 03 <42> 0f b6 04
    28 84 c0 0f 85 4b 02 00 00 41 0f b7 5e 12 49 8d 7e 14 RSP: 0018:ffffc9000b947c98 EFLAGS: 00010202 RAX:
    0000000000000002 RBX: ffff8880252ddf98 RCX: ffff888079478000 RDX: 0000000000000000 RSI: 0000000000000001
    RDI: 0000000000000012 RBP: 0000000000000001 R08: ffffffff8993e18d R09: 1ffffffff1fef385 R10:
    dffffc0000000000 R11: fffffbfff1fef386 R12: ffff8880252ddac0 R13: dffffc0000000000 R14: 0000000000000000
    R15: 0000000000000000 FS: 00007f24e45b96c0(0000) GS:ffff8880b9300000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007ffcced5f7b8 CR3: 00000000241be000 CR4: 00000000003506f0
    DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6:
    00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> __sctp_hash_endpoint net/sctp/input.c:762
    [inline] sctp_hash_endpoint+0x52a/0x600 net/sctp/input.c:790 sctp_listen_start net/sctp/socket.c:8570
    [inline] sctp_inet_listen+0x767/0xa20 net/sctp/socket.c:8625 __sys_listen_socket net/socket.c:1883
    [inline] __sys_listen+0x1b7/0x230 net/socket.c:1894 __do_sys_listen net/socket.c:1902 [inline]
    __se_sys_listen net/socket.c:1900 [inline] __x64_sys_listen+0x5a/0x70 net/socket.c:1900 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0033:0x7f24e46039b9 Code: 28 00 00 00 75 05 48 83 c4 28 c3
    e8 91 1a 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0
    ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007f24e45b9228 EFLAGS: 00000246
    ORIG_RAX: 0000000000000032 RAX: ffffffffffffffda RBX: 00007f24e468e428 RCX: 00007f24e46039b9 RDX:
    00007f24e46039b9 RSI: 0000000000000003 RDI: 0000000000000004 RBP: 00007f24e468e420 R08: 00007f24e45b96c0
    R09: 00007f24e45b96c0 R10: 00007f24e45b96c0 R11: 0000000000000246 R12: 00007f24e468e42c R13:
    ---truncated--- (CVE-2024-44935)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44935");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-azure-fde",
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
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "linux-azure-fde-5.15",
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
  },
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
