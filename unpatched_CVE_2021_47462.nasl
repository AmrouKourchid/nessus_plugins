#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229753);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47462");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47462");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/mempolicy: do not allow illegal
    MPOL_F_NUMA_BALANCING | MPOL_LOCAL in mbind() syzbot reported access to unitialized memory in mbind() [1]
    Issue came with commit bda420b98505 (numa balancing: migrate on fault among multiple bound nodes) This
    commit added a new bit in MPOL_MODE_FLAGS, but only checked valid combination (MPOL_F_NUMA_BALANCING can
    only be used with MPOL_BIND) in do_set_mempolicy() This patch moves the check in sanitize_mpol_flags() so
    that it is also used by mbind() [1] BUG: KMSAN: uninit-value in __mpol_equal+0x567/0x590
    mm/mempolicy.c:2260 __mpol_equal+0x567/0x590 mm/mempolicy.c:2260 mpol_equal include/linux/mempolicy.h:105
    [inline] vma_merge+0x4a1/0x1e60 mm/mmap.c:1190 mbind_range+0xcc8/0x1e80 mm/mempolicy.c:811
    do_mbind+0xf42/0x15f0 mm/mempolicy.c:1333 kernel_mbind mm/mempolicy.c:1483 [inline] __do_sys_mbind
    mm/mempolicy.c:1490 [inline] __se_sys_mbind+0x437/0xb80 mm/mempolicy.c:1486 __x64_sys_mbind+0x19d/0x200
    mm/mempolicy.c:1486 do_syscall_x64 arch/x86/entry/common.c:51 [inline] do_syscall_64+0x54/0xd0
    arch/x86/entry/common.c:82 entry_SYSCALL_64_after_hwframe+0x44/0xae Uninit was created at: slab_alloc_node
    mm/slub.c:3221 [inline] slab_alloc mm/slub.c:3230 [inline] kmem_cache_alloc+0x751/0xff0 mm/slub.c:3235
    mpol_new mm/mempolicy.c:293 [inline] do_mbind+0x912/0x15f0 mm/mempolicy.c:1289 kernel_mbind
    mm/mempolicy.c:1483 [inline] __do_sys_mbind mm/mempolicy.c:1490 [inline] __se_sys_mbind+0x437/0xb80
    mm/mempolicy.c:1486 __x64_sys_mbind+0x19d/0x200 mm/mempolicy.c:1486 do_syscall_x64
    arch/x86/entry/common.c:51 [inline] do_syscall_64+0x54/0xd0 arch/x86/entry/common.c:82
    entry_SYSCALL_64_after_hwframe+0x44/0xae ===================================================== Kernel
    panic - not syncing: panic_on_kmsan set ... CPU: 0 PID: 15049 Comm: syz-executor.0 Tainted: G B
    5.15.0-rc2-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google
    01/01/2011 Call Trace: __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0x1ff/0x28e
    lib/dump_stack.c:106 dump_stack+0x25/0x28 lib/dump_stack.c:113 panic+0x44f/0xdeb kernel/panic.c:232
    kmsan_report+0x2ee/0x300 mm/kmsan/report.c:186 __msan_warning+0xd7/0x150 mm/kmsan/instrumentation.c:208
    __mpol_equal+0x567/0x590 mm/mempolicy.c:2260 mpol_equal include/linux/mempolicy.h:105 [inline]
    vma_merge+0x4a1/0x1e60 mm/mmap.c:1190 mbind_range+0xcc8/0x1e80 mm/mempolicy.c:811 do_mbind+0xf42/0x15f0
    mm/mempolicy.c:1333 kernel_mbind mm/mempolicy.c:1483 [inline] __do_sys_mbind mm/mempolicy.c:1490 [inline]
    __se_sys_mbind+0x437/0xb80 mm/mempolicy.c:1486 __x64_sys_mbind+0x19d/0x200 mm/mempolicy.c:1486
    do_syscall_x64 arch/x86/entry/common.c:51 [inline] do_syscall_64+0x54/0xd0 arch/x86/entry/common.c:82
    entry_SYSCALL_64_after_hwframe+0x44/0xae (CVE-2021-47462)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47462");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
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
