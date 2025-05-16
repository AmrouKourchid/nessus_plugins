#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228733);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-46771");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-46771");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: can: bcm: Remove proc entry when dev
    is unregistered. syzkaller reported a warning in bcm_connect() below. [0] The repro calls connect() to
    vxcan1, removes vxcan1, and calls connect() with ifindex == 0. Calling connect() for a BCM socket
    allocates a proc entry. Then, bcm_sk(sk)->bound is set to 1 to prevent further connect(). However,
    removing the bound device resets bcm_sk(sk)->bound to 0 in bcm_notify(). The 2nd connect() tries to
    allocate a proc entry with the same name and sets NULL to bcm_sk(sk)->bcm_proc_read, leaking the original
    proc entry. Since the proc entry is available only for connect()ed sockets, let's clean up the entry when
    the bound netdev is unregistered. [0]: proc_dir_entry 'can-bcm/2456' already registered WARNING: CPU: 1
    PID: 394 at fs/proc/generic.c:376 proc_register+0x645/0x8f0 fs/proc/generic.c:375 Modules linked in: CPU:
    1 PID: 394 Comm: syz-executor403 Not tainted 6.10.0-rc7-g852e42cc2dd4 Hardware name: QEMU Standard PC
    (i440FX + PIIX, 1996), BIOS rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org 04/01/2014 RIP:
    0010:proc_register+0x645/0x8f0 fs/proc/generic.c:375 Code: 00 00 00 00 00 48 85 ed 0f 85 97 02 00 00 4d 85
    f6 0f 85 9f 02 00 00 48 c7 c7 9b cb cf 87 48 89 de 4c 89 fa e8 1c 6f eb fe 90 <0f> 0b 90 90 48 c7 c7 98 37
    99 89 e8 cb 7e 22 05 bb 00 00 00 10 48 RSP: 0018:ffa0000000cd7c30 EFLAGS: 00010246 RAX: 9e129be1950f0200
    RBX: ff1100011b51582c RCX: ff1100011857cd80 RDX: 0000000000000000 RSI: 0000000000000000 RDI:
    0000000000000002 RBP: 0000000000000000 R08: ffd400000000000f R09: ff1100013e78cac0 R10: ffac800000cd7980
    R11: ff1100013e12b1f0 R12: 0000000000000000 R13: 0000000000000000 R14: 0000000000000000 R15:
    ff1100011a99a2ec FS: 00007fbd7086f740(0000) GS:ff1100013fd00000(0000) knlGS:0000000000000000 CS: 0010 DS:
    0000 ES: 0000 CR0: 0000000080050033 CR2: 00000000200071c0 CR3: 0000000118556004 CR4: 0000000000771ef0 DR0:
    0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe07f0
    DR7: 0000000000000400 PKRU: 55555554 Call Trace: <TASK> proc_create_net_single+0x144/0x210
    fs/proc/proc_net.c:220 bcm_connect+0x472/0x840 net/can/bcm.c:1673 __sys_connect_file net/socket.c:2049
    [inline] __sys_connect+0x5d2/0x690 net/socket.c:2066 __do_sys_connect net/socket.c:2076 [inline]
    __se_sys_connect net/socket.c:2073 [inline] __x64_sys_connect+0x8f/0x100 net/socket.c:2073 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xd9/0x1c0 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x4b/0x53 RIP: 0033:0x7fbd708b0e5d Code: ff c3 66 2e 0f 1f 84 00 00 00 00
    00 90 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0
    ff ff 73 01 c3 48 8b 0d 73 9f 1b 00 f7 d8 64 89 01 48 RSP: 002b:00007fff8cd33f08 EFLAGS: 00000246
    ORIG_RAX: 000000000000002a RAX: ffffffffffffffda RBX: 0000000000000003 RCX: 00007fbd708b0e5d RDX:
    0000000000000010 RSI: 0000000020000040 RDI: 0000000000000003 RBP: 0000000000000000 R08: 0000000000000040
    R09: 0000000000000040 R10: 0000000000000040 R11: 0000000000000246 R12: 00007fff8cd34098 R13:
    0000000000401280 R14: 0000000000406de8 R15: 00007fbd70ab9000 </TASK> remove_proc_entry: removing non-empty
    directory 'net/can-bcm', leaking at least '2456' (CVE-2024-46771)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46771");

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
