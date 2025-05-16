#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229158);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-46782");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-46782");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ila: call nf_unregister_net_hooks()
    sooner syzbot found an use-after-free Read in ila_nf_input [1] Issue here is that ila_xlat_exit_net()
    frees the rhashtable, then call nf_unregister_net_hooks(). It should be done in the reverse way, with a
    synchronize_rcu(). This is a good match for a pre_exit() method. [1] BUG: KASAN: use-after-free in
    rht_key_hashfn include/linux/rhashtable.h:159 [inline] BUG: KASAN: use-after-free in __rhashtable_lookup
    include/linux/rhashtable.h:604 [inline] BUG: KASAN: use-after-free in rhashtable_lookup
    include/linux/rhashtable.h:646 [inline] BUG: KASAN: use-after-free in rhashtable_lookup_fast+0x77a/0x9b0
    include/linux/rhashtable.h:672 Read of size 4 at addr ffff888064620008 by task ksoftirqd/0/16 CPU: 0 UID:
    0 PID: 16 Comm: ksoftirqd/0 Not tainted 6.11.0-rc4-syzkaller-00238-g2ad6d23f465a #0 Hardware name: Google
    Google Compute Engine/Google Compute Engine, BIOS Google 08/06/2024 Call Trace: <TASK> __dump_stack
    lib/dump_stack.c:93 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:119 print_address_description
    mm/kasan/report.c:377 [inline] print_report+0x169/0x550 mm/kasan/report.c:488 kasan_report+0x143/0x180
    mm/kasan/report.c:601 rht_key_hashfn include/linux/rhashtable.h:159 [inline] __rhashtable_lookup
    include/linux/rhashtable.h:604 [inline] rhashtable_lookup include/linux/rhashtable.h:646 [inline]
    rhashtable_lookup_fast+0x77a/0x9b0 include/linux/rhashtable.h:672 ila_lookup_wildcards
    net/ipv6/ila/ila_xlat.c:132 [inline] ila_xlat_addr net/ipv6/ila/ila_xlat.c:652 [inline]
    ila_nf_input+0x1fe/0x3c0 net/ipv6/ila/ila_xlat.c:190 nf_hook_entry_hookfn include/linux/netfilter.h:154
    [inline] nf_hook_slow+0xc3/0x220 net/netfilter/core.c:626 nf_hook include/linux/netfilter.h:269 [inline]
    NF_HOOK+0x29e/0x450 include/linux/netfilter.h:312 __netif_receive_skb_one_core net/core/dev.c:5661
    [inline] __netif_receive_skb+0x1ea/0x650 net/core/dev.c:5775 process_backlog+0x662/0x15b0
    net/core/dev.c:6108 __napi_poll+0xcb/0x490 net/core/dev.c:6772 napi_poll net/core/dev.c:6841 [inline]
    net_rx_action+0x89b/0x1240 net/core/dev.c:6963 handle_softirqs+0x2c4/0x970 kernel/softirq.c:554
    run_ksoftirqd+0xca/0x130 kernel/softirq.c:928 smpboot_thread_fn+0x544/0xa30 kernel/smpboot.c:164
    kthread+0x2f0/0x390 kernel/kthread.c:389 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147
    ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244 </TASK> The buggy address belongs to the
    physical page: page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x64620 flags:
    0xfff00000000000(node=0|zone=1|lastcpupid=0x7ff) page_type: 0xbfffffff(buddy) raw: 00fff00000000000
    ffffea0000959608 ffffea00019d9408 0000000000000000 raw: 0000000000000000 0000000000000003 00000000bfffffff
    0000000000000000 page dumped because: kasan: bad access detected page_owner tracks the page as freed page
    last allocated via order 3, migratetype Unmovable, gfp_mask
    0x52dc0(GFP_KERNEL|__GFP_NOWARN|__GFP_NORETRY|__GFP_COMP|__GFP_ZERO), pid 5242, tgid 5242 (syz-executor),
    ts 73611328570, free_ts 618981657187 set_page_owner include/linux/page_owner.h:32 [inline]
    post_alloc_hook+0x1f3/0x230 mm/page_alloc.c:1493 prep_new_page mm/page_alloc.c:1501 [inline]
    get_page_from_freelist+0x2e4c/0x2f10 mm/page_alloc.c:3439 __alloc_pages_noprof+0x256/0x6c0
    mm/page_alloc.c:4695 __alloc_pages_node_noprof include/linux/gfp.h:269 [inline] alloc_pages_node_noprof
    include/linux/gfp.h:296 [inline] ___kmalloc_large_node+0x8b/0x1d0 mm/slub.c:4103
    __kmalloc_large_node_noprof+0x1a/0x80 mm/slub.c:4130 __do_kmalloc_node mm/slub.c:4146 [inline]
    __kmalloc_node_noprof+0x2d2/0x440 mm/slub.c:4164 __kvmalloc_node_noprof+0x72/0x190 mm/util.c:650
    bucket_table_alloc lib/rhashtable.c:186 [inline] rhashtable_init_noprof+0x534/0xa60 lib/rhashtable.c:1071
    ila_xlat_init_net+0xa0/0x110 net/ipv6/ila/ila_xlat.c:613 ops_ini ---truncated--- (CVE-2024-46782)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46782");

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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
