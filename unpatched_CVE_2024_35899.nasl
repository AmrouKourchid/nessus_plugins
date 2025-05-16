#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228578);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35899");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35899");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: flush pending
    destroy work before exit_net release Similar to 2c9f0293280e (netfilter: nf_tables: flush pending destroy
    work before netlink notifier) to address a race between exit_net and the destroy workqueue. The trace
    below shows an element to be released via destroy workqueue while exit_net path (triggered via module
    removal) has already released the set that is used in such transaction. [ 1360.547789] BUG: KASAN: slab-
    use-after-free in nf_tables_trans_destroy_work+0x3f5/0x590 [nf_tables] [ 1360.547861] Read of size 8 at
    addr ffff888140500cc0 by task kworker/4:1/152465 [ 1360.547870] CPU: 4 PID: 152465 Comm: kworker/4:1 Not
    tainted 6.8.0+ #359 [ 1360.547882] Workqueue: events nf_tables_trans_destroy_work [nf_tables] [
    1360.547984] Call Trace: [ 1360.547991] <TASK> [ 1360.547998] dump_stack_lvl+0x53/0x70 [ 1360.548014]
    print_report+0xc4/0x610 [ 1360.548026] ? __virt_addr_valid+0xba/0x160 [ 1360.548040] ?
    __pfx__raw_spin_lock_irqsave+0x10/0x10 [ 1360.548054] ? nf_tables_trans_destroy_work+0x3f5/0x590
    [nf_tables] [ 1360.548176] kasan_report+0xae/0xe0 [ 1360.548189] ?
    nf_tables_trans_destroy_work+0x3f5/0x590 [nf_tables] [ 1360.548312]
    nf_tables_trans_destroy_work+0x3f5/0x590 [nf_tables] [ 1360.548447] ?
    __pfx_nf_tables_trans_destroy_work+0x10/0x10 [nf_tables] [ 1360.548577] ? _raw_spin_unlock_irq+0x18/0x30 [
    1360.548591] process_one_work+0x2f1/0x670 [ 1360.548610] worker_thread+0x4d3/0x760 [ 1360.548627] ?
    __pfx_worker_thread+0x10/0x10 [ 1360.548640] kthread+0x16b/0x1b0 [ 1360.548653] ? __pfx_kthread+0x10/0x10
    [ 1360.548665] ret_from_fork+0x2f/0x50 [ 1360.548679] ? __pfx_kthread+0x10/0x10 [ 1360.548690]
    ret_from_fork_asm+0x1a/0x30 [ 1360.548707] </TASK> [ 1360.548719] Allocated by task 192061: [ 1360.548726]
    kasan_save_stack+0x20/0x40 [ 1360.548739] kasan_save_track+0x14/0x30 [ 1360.548750]
    __kasan_kmalloc+0x8f/0xa0 [ 1360.548760] __kmalloc_node+0x1f1/0x450 [ 1360.548771]
    nf_tables_newset+0x10c7/0x1b50 [nf_tables] [ 1360.548883] nfnetlink_rcv_batch+0xbc4/0xdc0 [nfnetlink] [
    1360.548909] nfnetlink_rcv+0x1a8/0x1e0 [nfnetlink] [ 1360.548927] netlink_unicast+0x367/0x4f0 [
    1360.548935] netlink_sendmsg+0x34b/0x610 [ 1360.548944] ____sys_sendmsg+0x4d4/0x510 [ 1360.548953]
    ___sys_sendmsg+0xc9/0x120 [ 1360.548961] __sys_sendmsg+0xbe/0x140 [ 1360.548971] do_syscall_64+0x55/0x120
    [ 1360.548982] entry_SYSCALL_64_after_hwframe+0x55/0x5d [ 1360.548994] Freed by task 192222: [
    1360.548999] kasan_save_stack+0x20/0x40 [ 1360.549009] kasan_save_track+0x14/0x30 [ 1360.549019]
    kasan_save_free_info+0x3b/0x60 [ 1360.549028] poison_slab_object+0x100/0x180 [ 1360.549036]
    __kasan_slab_free+0x14/0x30 [ 1360.549042] kfree+0xb6/0x260 [ 1360.549049] __nft_release_table+0x473/0x6a0
    [nf_tables] [ 1360.549131] nf_tables_exit_net+0x170/0x240 [nf_tables] [ 1360.549221]
    ops_exit_list+0x50/0xa0 [ 1360.549229] free_exit_list+0x101/0x140 [ 1360.549236]
    unregister_pernet_operations+0x107/0x160 [ 1360.549245] unregister_pernet_subsys+0x1c/0x30 [ 1360.549254]
    nf_tables_module_exit+0x43/0x80 [nf_tables] [ 1360.549345] __do_sys_delete_module+0x253/0x370 [
    1360.549352] do_syscall_64+0x55/0x120 [ 1360.549360] entry_SYSCALL_64_after_hwframe+0x55/0x5d (gdb) list
    *__nft_release_table+0x473 0x1e033 is in __nft_release_table (net/netfilter/nf_tables_api.c:11354). 11349
    list_for_each_entry_safe(flowtable, nf, &table->flowtables, list) { 11350 list_del(&flowtable->list);
    11351 nft_use_dec(&table->use); 11352 nf_tables_flowtable_destroy(flowtable); 11353 } 11354
    list_for_each_entry_safe(set, ns, &table->sets, list) { 11355 list_del(&set->list); 11356
    nft_use_dec(&table->use); 11357 if (set->flags & (NFT_SET_MAP | NFT_SET_OBJECT)) 11358 nft_map_deactivat
    ---truncated--- (CVE-2024-35899)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35899");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/10");
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
