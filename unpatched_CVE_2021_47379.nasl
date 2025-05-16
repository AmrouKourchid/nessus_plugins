#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230168);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47379");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47379");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: blk-cgroup: fix UAF by grabbing blkcg
    lock before destroying blkg pd KASAN reports a use-after-free report when doing fuzz test: [693354.104835]
    ================================================================== [693354.105094] BUG: KASAN: use-after-
    free in bfq_io_set_weight_legacy+0xd3/0x160 [693354.105336] Read of size 4 at addr ffff888be0a35664 by
    task sh/1453338 [693354.105607] CPU: 41 PID: 1453338 Comm: sh Kdump: loaded Not tainted 4.18.0-147
    [693354.105610] Hardware name: Huawei 2288H V5/BC11SPSCB0, BIOS 0.81 07/02/2018 [693354.105612] Call
    Trace: [693354.105621] dump_stack+0xf1/0x19b [693354.105626] ? show_regs_print_info+0x5/0x5
    [693354.105634] ? printk+0x9c/0xc3 [693354.105638] ? cpumask_weight+0x1f/0x1f [693354.105648]
    print_address_description+0x70/0x360 [693354.105654] kasan_report+0x1b2/0x330 [693354.105659] ?
    bfq_io_set_weight_legacy+0xd3/0x160 [693354.105665] ? bfq_io_set_weight_legacy+0xd3/0x160 [693354.105670]
    bfq_io_set_weight_legacy+0xd3/0x160 [693354.105675] ? bfq_cpd_init+0x20/0x20 [693354.105683]
    cgroup_file_write+0x3aa/0x510 [693354.105693] ? ___slab_alloc+0x507/0x540 [693354.105698] ?
    cgroup_file_poll+0x60/0x60 [693354.105702] ? 0xffffffff89600000 [693354.105708] ? usercopy_abort+0x90/0x90
    [693354.105716] ? mutex_lock+0xef/0x180 [693354.105726] kernfs_fop_write+0x1ab/0x280 [693354.105732] ?
    cgroup_file_poll+0x60/0x60 [693354.105738] vfs_write+0xe7/0x230 [693354.105744] ksys_write+0xb0/0x140
    [693354.105749] ? __ia32_sys_read+0x50/0x50 [693354.105760] do_syscall_64+0x112/0x370 [693354.105766] ?
    syscall_return_slowpath+0x260/0x260 [693354.105772] ? do_page_fault+0x9b/0x270 [693354.105779] ?
    prepare_exit_to_usermode+0xf9/0x1a0 [693354.105784] ? enter_from_user_mode+0x30/0x30 [693354.105793]
    entry_SYSCALL_64_after_hwframe+0x65/0xca [693354.105875] Allocated by task 1453337: [693354.106001]
    kasan_kmalloc+0xa0/0xd0 [693354.106006] kmem_cache_alloc_node_trace+0x108/0x220 [693354.106010]
    bfq_pd_alloc+0x96/0x120 [693354.106015] blkcg_activate_policy+0x1b7/0x2b0 [693354.106020]
    bfq_create_group_hierarchy+0x1e/0x80 [693354.106026] bfq_init_queue+0x678/0x8c0 [693354.106031]
    blk_mq_init_sched+0x1f8/0x460 [693354.106037] elevator_switch_mq+0xe1/0x240 [693354.106041]
    elevator_switch+0x25/0x40 [693354.106045] elv_iosched_store+0x1a1/0x230 [693354.106049]
    queue_attr_store+0x78/0xb0 [693354.106053] kernfs_fop_write+0x1ab/0x280 [693354.106056]
    vfs_write+0xe7/0x230 [693354.106060] ksys_write+0xb0/0x140 [693354.106064] do_syscall_64+0x112/0x370
    [693354.106069] entry_SYSCALL_64_after_hwframe+0x65/0xca [693354.106114] Freed by task 1453336:
    [693354.106225] __kasan_slab_free+0x130/0x180 [693354.106229] kfree+0x90/0x1b0 [693354.106233]
    blkcg_deactivate_policy+0x12c/0x220 [693354.106238] bfq_exit_queue+0xf5/0x110 [693354.106241]
    blk_mq_exit_sched+0x104/0x130 [693354.106245] __elevator_exit+0x45/0x60 [693354.106249]
    elevator_switch_mq+0xd6/0x240 [693354.106253] elevator_switch+0x25/0x40 [693354.106257]
    elv_iosched_store+0x1a1/0x230 [693354.106261] queue_attr_store+0x78/0xb0 [693354.106264]
    kernfs_fop_write+0x1ab/0x280 [693354.106268] vfs_write+0xe7/0x230 [693354.106271] ksys_write+0xb0/0x140
    [693354.106275] do_syscall_64+0x112/0x370 [693354.106280] entry_SYSCALL_64_after_hwframe+0x65/0xca
    [693354.106329] The buggy address belongs to the object at ffff888be0a35580 which belongs to the cache
    kmalloc-1k of size 1024 [693354.106736] The buggy address is located 228 bytes inside of 1024-byte region
    [ffff888be0a35580, ffff888be0a35980) [693354.107114] The buggy address belongs to the page:
    [693354.107273] page:ffffea002f828c00 count:1 mapcount:0 mapping:ffff888107c17080 index:0x0
    compound_mapcount: 0 [693354.107606] flags: 0x17ffffc0008100(slab|head) [693354.107760] raw:
    0017ffffc0008100 ffffea002fcbc808 ffffea0030bd3a08 ffff888107c17080 [693354.108020] r ---truncated---
    (CVE-2021-47379)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47379");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
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
