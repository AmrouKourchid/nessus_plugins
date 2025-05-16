#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226054);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52745");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52745");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: IB/IPoIB: Fix legacy IPoIB due to
    wrong number of queues The cited commit creates child PKEY interfaces over netlink will multiple tx and rx
    queues, but some devices doesn't support more than 1 tx and 1 rx queues. This causes to a crash when
    traffic is sent over the PKEY interface due to the parent having a single queue but the child having
    multiple queues. This patch fixes the number of queues to 1 for legacy IPoIB at the earliest possible
    point in time. BUG: kernel NULL pointer dereference, address: 000000000000036b PGD 0 P4D 0 Oops: 0000 [#1]
    SMP CPU: 4 PID: 209665 Comm: python3 Not tainted 6.1.0_for_upstream_min_debug_2022_12_12_17_02 #1 Hardware
    name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
    RIP: 0010:kmem_cache_alloc+0xcb/0x450 Code: ce 7e 49 8b 50 08 49 83 78 10 00 4d 8b 28 0f 84 cb 02 00 00 4d
    85 ed 0f 84 c2 02 00 00 41 8b 44 24 28 48 8d 4a 01 49 8b 3c 24 <49> 8b 5c 05 00 4c 89 e8 65 48 0f c7 0f 0f
    94 c0 84 c0 74 b8 41 8b RSP: 0018:ffff88822acbbab8 EFLAGS: 00010202 RAX: 0000000000000070 RBX:
    ffff8881c28e3e00 RCX: 00000000064f8dae RDX: 00000000064f8dad RSI: 0000000000000a20 RDI: 0000000000030d00
    RBP: 0000000000000a20 R08: ffff8882f5d30d00 R09: ffff888104032f40 R10: ffff88810fade828 R11:
    736f6d6570736575 R12: ffff88810081c000 R13: 00000000000002fb R14: ffffffff817fc865 R15: 0000000000000000
    FS: 00007f9324ff9700(0000) GS:ffff8882f5d00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 CR2: 000000000000036b CR3: 00000001125af004 CR4: 0000000000370ea0 DR0:
    0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0
    DR7: 0000000000000400 Call Trace: <TASK> skb_clone+0x55/0xd0 ip6_finish_output2+0x3fe/0x690
    ip6_finish_output+0xfa/0x310 ip6_send_skb+0x1e/0x60 udp_v6_send_skb+0x1e5/0x420 udpv6_sendmsg+0xb3c/0xe60
    ? ip_mc_finish_output+0x180/0x180 ? __switch_to_asm+0x3a/0x60 ? __switch_to_asm+0x34/0x60
    sock_sendmsg+0x33/0x40 __sys_sendto+0x103/0x160 ? _copy_to_user+0x21/0x30 ? kvm_clock_get_cycles+0xd/0x10
    ? ktime_get_ts64+0x49/0xe0 __x64_sys_sendto+0x25/0x30 do_syscall_64+0x3d/0x90
    entry_SYSCALL_64_after_hwframe+0x46/0xb0 RIP: 0033:0x7f9374f1ed14 Code: 42 41 f8 ff 44 8b 4c 24 2c 4c 8b
    44 24 20 89 c5 44 8b 54 24 28 48 8b 54 24 18 b8 2c 00 00 00 48 8b 74 24 10 8b 7c 24 08 0f 05 <48> 3d 00 f0
    ff ff 77 34 89 ef 48 89 44 24 08 e8 68 41 f8 ff 48 8b RSP: 002b:00007f9324ff7bd0 EFLAGS: 00000293
    ORIG_RAX: 000000000000002c RAX: ffffffffffffffda RBX: 00007f9324ff7cc8 RCX: 00007f9374f1ed14 RDX:
    00000000000002fb RSI: 00007f93000052f0 RDI: 0000000000000030 RBP: 0000000000000000 R08: 00007f9324ff7d40
    R09: 000000000000001c R10: 0000000000000000 R11: 0000000000000293 R12: 0000000000000000 R13:
    000000012a05f200 R14: 0000000000000001 R15: 00007f9374d57bdc </TASK> (CVE-2023-52745)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/17");
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
    "name": "kernel",
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
        "os_version": "8"
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
