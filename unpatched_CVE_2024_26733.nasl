#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227644);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26733");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26733");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: arp: Prevent overflow in
    arp_req_get(). syzkaller reported an overflown write in arp_req_get(). [0] When ioctl(SIOCGARP) is issued,
    arp_req_get() looks up an neighbour entry and copies neigh->ha to struct arpreq.arp_ha.sa_data. The arp_ha
    here is struct sockaddr, not struct sockaddr_storage, so the sa_data buffer is just 14 bytes. In the splat
    below, 2 bytes are overflown to the next int field, arp_flags. We initialise the field just after the
    memcpy(), so it's not a problem. However, when dev->addr_len is greater than 22 (e.g. MAX_ADDR_LEN),
    arp_netmask is overwritten, which could be set as htonl(0xFFFFFFFFUL) in arp_ioctl() before calling
    arp_req_get(). To avoid the overflow, let's limit the max length of memcpy(). Note that commit
    b5f0de6df6dc (net: dev: Convert sa_data to flexible array in struct sockaddr) just silenced syzkaller.
    [0]: memcpy: detected field-spanning write (size 16) of single field r->arp_ha.sa_data at
    net/ipv4/arp.c:1128 (size 14) WARNING: CPU: 0 PID: 144638 at net/ipv4/arp.c:1128 arp_req_get+0x411/0x4a0
    net/ipv4/arp.c:1128 Modules linked in: CPU: 0 PID: 144638 Comm: syz-executor.4 Not tainted 6.1.74 #31
    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-5 04/01/2014 RIP:
    0010:arp_req_get+0x411/0x4a0 net/ipv4/arp.c:1128 Code: fd ff ff e8 41 42 de fb b9 0e 00 00 00 4c 89 fe 48
    c7 c2 20 6d ab 87 48 c7 c7 80 6d ab 87 c6 05 25 af 72 04 01 e8 5f 8d ad fb <0f> 0b e9 6c fd ff ff e8 13 42
    de fb be 03 00 00 00 4c 89 e7 e8 a6 RSP: 0018:ffffc900050b7998 EFLAGS: 00010286 RAX: 0000000000000000 RBX:
    ffff88803a815000 RCX: 0000000000000000 RDX: 0000000000000000 RSI: ffffffff8641a44a RDI: 0000000000000001
    RBP: ffffc900050b7a98 R08: 0000000000000001 R09: 0000000000000000 R10: 0000000000000000 R11:
    203a7970636d656d R12: ffff888039c54000 R13: 1ffff92000a16f37 R14: ffff88803a815084 R15: 0000000000000010
    FS: 00007f172bf306c0(0000) GS:ffff88805aa00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 CR2: 00007f172b3569f0 CR3: 0000000057f12005 CR4: 0000000000770ef0 DR0:
    0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0
    DR7: 0000000000000400 PKRU: 55555554 Call Trace: <TASK> arp_ioctl+0x33f/0x4b0 net/ipv4/arp.c:1261
    inet_ioctl+0x314/0x3a0 net/ipv4/af_inet.c:981 sock_do_ioctl+0xdf/0x260 net/socket.c:1204
    sock_ioctl+0x3ef/0x650 net/socket.c:1321 vfs_ioctl fs/ioctl.c:51 [inline] __do_sys_ioctl fs/ioctl.c:870
    [inline] __se_sys_ioctl fs/ioctl.c:856 [inline] __x64_sys_ioctl+0x18e/0x220 fs/ioctl.c:856 do_syscall_x64
    arch/x86/entry/common.c:51 [inline] do_syscall_64+0x37/0x90 arch/x86/entry/common.c:81
    entry_SYSCALL_64_after_hwframe+0x64/0xce RIP: 0033:0x7f172b262b8d Code: 66 2e 0f 1f 84 00 00 00 00 00 0f
    1f 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0
    ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007f172bf300b8 EFLAGS: 00000246
    ORIG_RAX: 0000000000000010 RAX: ffffffffffffffda RBX: 00007f172b3abf80 RCX: 00007f172b262b8d RDX:
    0000000020000000 RSI: 0000000000008954 RDI: 0000000000000003 RBP: 00007f172b2d3493 R08: 0000000000000000
    R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000 R13:
    000000000000000b R14: 00007f172b3abf80 R15: 00007f172bf10000 </TASK> (CVE-2024-26733)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
