#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229863);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-46954");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-46954");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/sched: sch_frag: fix stack OOB
    read while fragmenting IPv4 packets when 'act_mirred' tries to fragment IPv4 packets that had been
    previously re-assembled using 'act_ct', splats like the following can be observed on kernels built with
    KASAN: BUG: KASAN: stack-out-of-bounds in ip_do_fragment+0x1b03/0x1f60 Read of size 1 at addr
    ffff888147009574 by task ping/947 CPU: 0 PID: 947 Comm: ping Not tainted 5.12.0-rc6+ #418 Hardware name:
    Red Hat KVM, BIOS 1.11.1-4.module+el8.1.0+4066+0f1aadab 04/01/2014 Call Trace: <IRQ> dump_stack+0x92/0xc1
    print_address_description.constprop.7+0x1a/0x150 kasan_report.cold.13+0x7f/0x111
    ip_do_fragment+0x1b03/0x1f60 sch_fragment+0x4bf/0xe40 tcf_mirred_act+0xc3d/0x11a0 [act_mirred]
    tcf_action_exec+0x104/0x3e0 fl_classify+0x49a/0x5e0 [cls_flower] tcf_classify_ingress+0x18a/0x820
    __netif_receive_skb_core+0xae7/0x3340 __netif_receive_skb_one_core+0xb6/0x1b0 process_backlog+0x1ef/0x6c0
    __napi_poll+0xaa/0x500 net_rx_action+0x702/0xac0 __do_softirq+0x1e4/0x97f do_softirq+0x71/0x90 </IRQ>
    __local_bh_enable_ip+0xdb/0xf0 ip_finish_output2+0x760/0x2120 ip_do_fragment+0x15a5/0x1f60
    __ip_finish_output+0x4c2/0xea0 ip_output+0x1ca/0x4d0 ip_send_skb+0x37/0xa0 raw_sendmsg+0x1c4b/0x2d00
    sock_sendmsg+0xdb/0x110 __sys_sendto+0x1d7/0x2b0 __x64_sys_sendto+0xdd/0x1b0 do_syscall_64+0x33/0x40
    entry_SYSCALL_64_after_hwframe+0x44/0xae RIP: 0033:0x7f82e13853eb Code: 66 2e 0f 1f 84 00 00 00 00 00 0f
    1f 44 00 00 f3 0f 1e fa 48 8d 05 75 42 2c 00 41 89 ca 8b 00 85 c0 75 14 b8 2c 00 00 00 0f 05 <48> 3d 00 f0
    ff ff 77 75 c3 0f 1f 40 00 41 57 4d 89 c7 41 56 41 89 RSP: 002b:00007ffe01fad888 EFLAGS: 00000246
    ORIG_RAX: 000000000000002c RAX: ffffffffffffffda RBX: 00005571aac13700 RCX: 00007f82e13853eb RDX:
    0000000000002330 RSI: 00005571aac13700 RDI: 0000000000000003 RBP: 0000000000002330 R08: 00005571aac10500
    R09: 0000000000000010 R10: 0000000000000000 R11: 0000000000000246 R12: 00007ffe01faefb0 R13:
    00007ffe01fad890 R14: 00007ffe01fad980 R15: 00005571aac0f0a0 The buggy address belongs to the page:
    page:000000001dff2e03 refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x147009 flags:
    0x17ffffc0001000(reserved) raw: 0017ffffc0001000 ffffea00051c0248 ffffea00051c0248 0000000000000000 raw:
    0000000000000000 0000000000000000 00000001ffffffff 0000000000000000 page dumped because: kasan: bad access
    detected Memory state around the buggy address: ffff888147009400: 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 ffff888147009480: f1 f1 f1 f1 04 f2 f2 f2 f2 f2 f2 f2 00 00 00 00 >ffff888147009500: 00 00 00 00
    00 00 00 00 00 00 f2 f2 f2 f2 f2 f2 ^ ffff888147009580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    ffff888147009600: 00 00 00 00 00 00 00 00 00 00 00 00 00 f2 f2 f2 for IPv4 packets, sch_fragment() uses a
    temporary struct dst_entry. Then, in the following call graph: ip_do_fragment() ip_skb_dst_mtu()
    ip_dst_mtu_maybe_forward() ip_mtu_locked() the pointer to struct dst_entry is used as pointer to struct
    rtable: this turns the access to struct members like rt_mtu_locked into an OOB read in the stack. Fix this
    changing the temporary variable used for IPv4 packets in sch_fragment(), similarly to what is done for
    IPv6 few lines below. (CVE-2021-46954)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-46954");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/27");
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
    "name": "linux-bluefield",
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
