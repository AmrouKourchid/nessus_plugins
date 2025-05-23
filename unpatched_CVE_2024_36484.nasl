#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229030);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36484");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36484");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: relax socket state check at
    accept time. Christoph reported the following splat: WARNING: CPU: 1 PID: 772 at net/ipv4/af_inet.c:761
    __inet_accept+0x1f4/0x4a0 Modules linked in: CPU: 1 PID: 772 Comm: syz-executor510 Not tainted
    6.9.0-rc7-g7da7119fe22b #56 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.0-2.el7
    04/01/2014 RIP: 0010:__inet_accept+0x1f4/0x4a0 net/ipv4/af_inet.c:759 Code: 04 38 84 c0 0f 85 87 00 00 00
    41 c7 04 24 03 00 00 00 48 83 c4 10 5b 41 5c 41 5d 41 5e 41 5f 5d c3 cc cc cc cc e8 ec b7 da fd <0f> 0b e9
    7f fe ff ff e8 e0 b7 da fd 0f 0b e9 fe fe ff ff 89 d9 80 RSP: 0018:ffffc90000c2fc58 EFLAGS: 00010293 RAX:
    ffffffff836bdd14 RBX: 0000000000000000 RCX: ffff888104668000 RDX: 0000000000000000 RSI: 0000000000000000
    RDI: 0000000000000000 RBP: dffffc0000000000 R08: ffffffff836bdb89 R09: fffff52000185f64 R10:
    dffffc0000000000 R11: fffff52000185f64 R12: dffffc0000000000 R13: 1ffff92000185f98 R14: ffff88810754d880
    R15: ffff8881007b7800 FS: 000000001c772880(0000) GS:ffff88811b280000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fb9fcf2e178 CR3: 00000001045d2002 CR4: 0000000000770ef0
    DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6:
    00000000fffe0ff0 DR7: 0000000000000400 PKRU: 55555554 Call Trace: <TASK> inet_accept+0x138/0x1d0
    net/ipv4/af_inet.c:786 do_accept+0x435/0x620 net/socket.c:1929 __sys_accept4_file net/socket.c:1969
    [inline] __sys_accept4+0x9b/0x110 net/socket.c:1999 __do_sys_accept net/socket.c:2016 [inline]
    __se_sys_accept net/socket.c:2013 [inline] __x64_sys_accept+0x7d/0x90 net/socket.c:2013 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0x58/0x100 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x76/0x7e RIP: 0033:0x4315f9 Code: fd ff 48 81 c4 80 00 00 00 e9 f1 fe ff
    ff 0f 1f 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff
    0f 83 ab b4 fd ff c3 66 2e 0f 1f 84 00 00 00 00 RSP: 002b:00007ffdb26d9c78 EFLAGS: 00000246 ORIG_RAX:
    000000000000002b RAX: ffffffffffffffda RBX: 0000000000400300 RCX: 00000000004315f9 RDX: 0000000000000000
    RSI: 0000000000000000 RDI: 0000000000000004 RBP: 00000000006e1018 R08: 0000000000400300 R09:
    0000000000400300 R10: 0000000000400300 R11: 0000000000000246 R12: 0000000000000000 R13: 000000000040cdf0
    R14: 000000000040ce80 R15: 0000000000000055 </TASK> The reproducer invokes shutdown() before entering the
    listener status. After commit 94062790aedb (tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV
    sockets), the above causes the child to reach the accept syscall in FIN_WAIT1 status. Eric noted we can
    relax the existing assertion in __inet_accept() (CVE-2024-36484)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36484");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/21");
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
