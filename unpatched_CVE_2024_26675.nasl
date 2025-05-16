#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228115);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26675");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26675");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ppp_async: limit MRU to 64K syzbot
    triggered a warning [1] in __alloc_pages(): WARN_ON_ONCE_GFP(order > MAX_PAGE_ORDER, gfp) Willem fixed a
    similar issue in commit c0a2a1b0d631 (ppp: limit MRU to 64K) Adopt the same sanity check for
    ppp_async_ioctl(PPPIOCSMRU) [1]: WARNING: CPU: 1 PID: 11 at mm/page_alloc.c:4543 __alloc_pages+0x308/0x698
    mm/page_alloc.c:4543 Modules linked in: CPU: 1 PID: 11 Comm: kworker/u4:0 Not tainted
    6.8.0-rc2-syzkaller-g41bccc98fb79 #0 Hardware name: Google Google Compute Engine/Google Compute Engine,
    BIOS Google 11/17/2023 Workqueue: events_unbound flush_to_ldisc pstate: 204000c5 (nzCv daIF +PAN -UAO -TCO
    -DIT -SSBS BTYPE=--) pc : __alloc_pages+0x308/0x698 mm/page_alloc.c:4543 lr : __alloc_pages+0xc8/0x698
    mm/page_alloc.c:4537 sp : ffff800093967580 x29: ffff800093967660 x28: ffff8000939675a0 x27:
    dfff800000000000 x26: ffff70001272ceb4 x25: 0000000000000000 x24: ffff8000939675c0 x23: 0000000000000000
    x22: 0000000000060820 x21: 1ffff0001272ceb8 x20: ffff8000939675e0 x19: 0000000000000010 x18:
    ffff800093967120 x17: ffff800083bded5c x16: ffff80008ac97500 x15: 0000000000000005 x14: 1ffff0001272cebc
    x13: 0000000000000000 x12: 0000000000000000 x11: ffff70001272cec1 x10: 1ffff0001272cec0 x9 :
    0000000000000001 x8 : ffff800091c91000 x7 : 0000000000000000 x6 : 000000000000003f x5 : 00000000ffffffff
    x4 : 0000000000000000 x3 : 0000000000000020 x2 : 0000000000000008 x1 : 0000000000000000 x0 :
    ffff8000939675e0 Call trace: __alloc_pages+0x308/0x698 mm/page_alloc.c:4543 __alloc_pages_node
    include/linux/gfp.h:238 [inline] alloc_pages_node include/linux/gfp.h:261 [inline]
    __kmalloc_large_node+0xbc/0x1fc mm/slub.c:3926 __do_kmalloc_node mm/slub.c:3969 [inline]
    __kmalloc_node_track_caller+0x418/0x620 mm/slub.c:4001 kmalloc_reserve+0x17c/0x23c net/core/skbuff.c:590
    __alloc_skb+0x1c8/0x3d8 net/core/skbuff.c:651 __netdev_alloc_skb+0xb8/0x3e8 net/core/skbuff.c:715
    netdev_alloc_skb include/linux/skbuff.h:3235 [inline] dev_alloc_skb include/linux/skbuff.h:3248 [inline]
    ppp_async_input drivers/net/ppp/ppp_async.c:863 [inline] ppp_asynctty_receive+0x588/0x186c
    drivers/net/ppp/ppp_async.c:341 tty_ldisc_receive_buf+0x12c/0x15c drivers/tty/tty_buffer.c:390
    tty_port_default_receive_buf+0x74/0xac drivers/tty/tty_port.c:37 receive_buf drivers/tty/tty_buffer.c:444
    [inline] flush_to_ldisc+0x284/0x6e4 drivers/tty/tty_buffer.c:494 process_one_work+0x694/0x1204
    kernel/workqueue.c:2633 process_scheduled_works kernel/workqueue.c:2706 [inline] worker_thread+0x938/0xef4
    kernel/workqueue.c:2787 kthread+0x288/0x310 kernel/kthread.c:388 ret_from_fork+0x10/0x20
    arch/arm64/kernel/entry.S:860 (CVE-2024-26675)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26675");

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
