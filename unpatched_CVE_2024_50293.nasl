#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230865);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-50293");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-50293");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/smc: do not leave a dangling sk
    pointer in __smc_create() Thanks to commit 4bbd360a5084 (socket: Print pf->create() when it does not
    clear sock->sk on failure.), syzbot found an issue with AF_SMC: smc_create must clear sock->sk on
    failure, family: 43, type: 1, protocol: 0 WARNING: CPU: 0 PID: 5827 at net/socket.c:1565
    __sock_create+0x96f/0xa30 net/socket.c:1563 Modules linked in: CPU: 0 UID: 0 PID: 5827 Comm: syz-
    executor259 Not tainted 6.12.0-rc6-next-20241106-syzkaller #0 Hardware name: Google Google Compute
    Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:__sock_create+0x96f/0xa30 net/socket.c:1563
    Code: 03 00 74 08 4c 89 e7 e8 4f 3b 85 f8 49 8b 34 24 48 c7 c7 40 89 0c 8d 8b 54 24 04 8b 4c 24 0c 44 8b
    44 24 08 e8 32 78 db f7 90 <0f> 0b 90 90 e9 d3 fd ff ff 89 e9 80 e1 07 fe c1 38 c1 0f 8c ee f7 RSP:
    0018:ffffc90003e4fda0 EFLAGS: 00010246 RAX: 099c6f938c7f4700 RBX: 1ffffffff1a595fd RCX: ffff888034823c00
    RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000 RBP: 00000000ffffffe9 R08:
    ffffffff81567052 R09: 1ffff920007c9f50 R10: dffffc0000000000 R11: fffff520007c9f51 R12: ffffffff8d2cafe8
    R13: 1ffffffff1a595fe R14: ffffffff9a789c40 R15: ffff8880764298c0 FS: 000055557b518380(0000)
    GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007fa62ff43225 CR3: 0000000031628000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK>
    sock_create net/socket.c:1616 [inline] __sys_socket_create net/socket.c:1653 [inline]
    __sys_socket+0x150/0x3c0 net/socket.c:1700 __do_sys_socket net/socket.c:1714 [inline] __se_sys_socket
    net/socket.c:1712 [inline] For reference, see commit 2d859aff775d (Merge branch 'do-not-leave-dangling-
    sk-pointers-in-pf-create-functions') (CVE-2024-50293)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50293");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
    "name": "linux-lowlatency-hwe-6.11",
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
        "os_version": "24.04"
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
