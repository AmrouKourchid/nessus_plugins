#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229403);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-39474");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-39474");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/vmalloc: fix vmalloc which may
    return null if called with __GFP_NOFAIL commit a421ef303008 (mm: allow !GFP_KERNEL allocations for
    kvmalloc) includes support for __GFP_NOFAIL, but it presents a conflict with commit dd544141b9eb
    (vmalloc: back off when the current task is OOM-killed). A possible scenario is as follows: process-a
    __vmalloc_node_range(GFP_KERNEL | __GFP_NOFAIL) __vmalloc_area_node() vm_area_alloc_pages() --> oom-killer
    send SIGKILL to process-a if (fatal_signal_pending(current)) break; --> return NULL; To fix this, do not
    check fatal_signal_pending() in vm_area_alloc_pages() if __GFP_NOFAIL set. This issue occurred during
    OPLUS KASAN TEST. Below is part of the log -> oom-killer sends signal to process [65731.222840] [ T1308]
    oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/apps/ui
    d_10198,task=gs.intelligence,pid=32454,uid=10198 [65731.259685] [T32454] Call trace: [65731.259698]
    [T32454] dump_backtrace+0xf4/0x118 [65731.259734] [T32454] show_stack+0x18/0x24 [65731.259756] [T32454]
    dump_stack_lvl+0x60/0x7c [65731.259781] [T32454] dump_stack+0x18/0x38 [65731.259800] [T32454]
    mrdump_common_die+0x250/0x39c [mrdump] [65731.259936] [T32454] ipanic_die+0x20/0x34 [mrdump]
    [65731.260019] [T32454] atomic_notifier_call_chain+0xb4/0xfc [65731.260047] [T32454]
    notify_die+0x114/0x198 [65731.260073] [T32454] die+0xf4/0x5b4 [65731.260098] [T32454]
    die_kernel_fault+0x80/0x98 [65731.260124] [T32454] __do_kernel_fault+0x160/0x2a8 [65731.260146] [T32454]
    do_bad_area+0x68/0x148 [65731.260174] [T32454] do_mem_abort+0x151c/0x1b34 [65731.260204] [T32454]
    el1_abort+0x3c/0x5c [65731.260227] [T32454] el1h_64_sync_handler+0x54/0x90 [65731.260248] [T32454]
    el1h_64_sync+0x68/0x6c [65731.260269] [T32454] z_erofs_decompress_queue+0x7f0/0x2258 -->
    be->decompressed_pages = kvcalloc(be->nr_pages, sizeof(struct page *), GFP_KERNEL | __GFP_NOFAIL); kernel
    panic by NULL pointer dereference. erofs assume kvmalloc with __GFP_NOFAIL never return NULL.
    [65731.260293] [T32454] z_erofs_runqueue+0xf30/0x104c [65731.260314] [T32454]
    z_erofs_readahead+0x4f0/0x968 [65731.260339] [T32454] read_pages+0x170/0xadc [65731.260364] [T32454]
    page_cache_ra_unbounded+0x874/0xf30 [65731.260388] [T32454] page_cache_ra_order+0x24c/0x714 [65731.260411]
    [T32454] filemap_fault+0xbf0/0x1a74 [65731.260437] [T32454] __do_fault+0xd0/0x33c [65731.260462] [T32454]
    handle_mm_fault+0xf74/0x3fe0 [65731.260486] [T32454] do_mem_abort+0x54c/0x1b34 [65731.260509] [T32454]
    el0_da+0x44/0x94 [65731.260531] [T32454] el0t_64_sync_handler+0x98/0xb4 [65731.260553] [T32454]
    el0t_64_sync+0x198/0x19c (CVE-2024-39474)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39474");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/05");
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
