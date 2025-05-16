#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228972);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-46783");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-46783");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tcp_bpf: fix return value of
    tcp_bpf_sendmsg() When we cork messages in psock->cork, the last message triggers the flushing will result
    in sending a sk_msg larger than the current message size. In this case, in tcp_bpf_send_verdict(),
    'copied' becomes negative at least in the following case: 468 case __SK_DROP: 469 default: 470
    sk_msg_free_partial(sk, msg, tosend); 471 sk_msg_apply_bytes(psock, tosend); 472 *copied -= (tosend +
    delta); // <==== HERE 473 return -EACCES; Therefore, it could lead to the following BUG with a proper
    value of 'copied' (thanks to syzbot). We should not use negative 'copied' as a return value here.
    ------------[ cut here ]------------ kernel BUG at net/socket.c:733! Internal error: Oops - BUG:
    00000000f2000800 [#1] PREEMPT SMP Modules linked in: CPU: 0 UID: 0 PID: 3265 Comm: syz-executor510 Not
    tainted 6.11.0-rc3-syzkaller-00060-gd07b43284ab3 #0 Hardware name: linux,dummy-virt (DT) pstate: 61400009
    (nZCv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=--) pc : sock_sendmsg_nosec net/socket.c:733 [inline] pc :
    sock_sendmsg_nosec net/socket.c:728 [inline] pc : __sock_sendmsg+0x5c/0x60 net/socket.c:745 lr :
    sock_sendmsg_nosec net/socket.c:730 [inline] lr : __sock_sendmsg+0x54/0x60 net/socket.c:745 sp :
    ffff800088ea3b30 x29: ffff800088ea3b30 x28: fbf00000062bc900 x27: 0000000000000000 x26: ffff800088ea3bc0
    x25: ffff800088ea3bc0 x24: 0000000000000000 x23: f9f00000048dc000 x22: 0000000000000000 x21:
    ffff800088ea3d90 x20: f9f00000048dc000 x19: ffff800088ea3d90 x18: 0000000000000001 x17: 0000000000000000
    x16: 0000000000000000 x15: 000000002002ffaf x14: 0000000000000000 x13: 0000000000000000 x12:
    0000000000000000 x11: 0000000000000000 x10: ffff8000815849c0 x9 : ffff8000815b49c0 x8 : 0000000000000000
    x7 : 000000000000003f x6 : 0000000000000000 x5 : 00000000000007e0 x4 : fff07ffffd239000 x3 :
    fbf00000062bc900 x2 : 0000000000000000 x1 : 0000000000000000 x0 : 00000000fffffdef Call trace:
    sock_sendmsg_nosec net/socket.c:733 [inline] __sock_sendmsg+0x5c/0x60 net/socket.c:745
    ____sys_sendmsg+0x274/0x2ac net/socket.c:2597 ___sys_sendmsg+0xac/0x100 net/socket.c:2651
    __sys_sendmsg+0x84/0xe0 net/socket.c:2680 __do_sys_sendmsg net/socket.c:2689 [inline] __se_sys_sendmsg
    net/socket.c:2687 [inline] __arm64_sys_sendmsg+0x24/0x30 net/socket.c:2687 __invoke_syscall
    arch/arm64/kernel/syscall.c:35 [inline] invoke_syscall+0x48/0x110 arch/arm64/kernel/syscall.c:49
    el0_svc_common.constprop.0+0x40/0xe0 arch/arm64/kernel/syscall.c:132 do_el0_svc+0x1c/0x28
    arch/arm64/kernel/syscall.c:151 el0_svc+0x34/0xec arch/arm64/kernel/entry-common.c:712
    el0t_64_sync_handler+0x100/0x12c arch/arm64/kernel/entry-common.c:730 el0t_64_sync+0x19c/0x1a0
    arch/arm64/kernel/entry.S:598 Code: f9404463 d63f0060 3108441f 54fffe81 (d4210000) ---[ end trace
    0000000000000000 ]--- (CVE-2024-46783)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46783");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/18");
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
