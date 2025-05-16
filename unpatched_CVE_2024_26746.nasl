#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227547);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26746");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26746");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: dmaengine: idxd: Ensure safe user copy
    of completion record If CONFIG_HARDENED_USERCOPY is enabled, copying completion record from event log
    cache to user triggers a kernel bug. [ 1987.159822] usercopy: Kernel memory exposure attempt detected from
    SLUB object 'dsa0' (offset 74, size 31)! [ 1987.170845] ------------[ cut here ]------------ [
    1987.176086] kernel BUG at mm/usercopy.c:102! [ 1987.180946] invalid opcode: 0000 [#1] PREEMPT SMP NOPTI [
    1987.186866] CPU: 17 PID: 528 Comm: kworker/17:1 Not tainted 6.8.0-rc2+ #5 [ 1987.194537] Hardware name:
    Intel Corporation AvenueCity/AvenueCity, BIOS BHSDCRB1.86B.2492.D03.2307181620 07/18/2023 [ 1987.206405]
    Workqueue: wq0.0 idxd_evl_fault_work [idxd] [ 1987.212338] RIP: 0010:usercopy_abort+0x72/0x90 [
    1987.217381] Code: 58 65 9c 50 48 c7 c2 17 85 61 9c 57 48 c7 c7 98 fd 6b 9c 48 0f 44 d6 48 c7 c6 b3 08 62
    9c 4c 89 d1 49 0f 44 f3 e8 1e 2e d5 ff <0f> 0b 49 c7 c1 9e 42 61 9c 4c 89 cf 4d 89 c8 eb a9 66 66 2e 0f 1f
    [ 1987.238505] RSP: 0018:ff62f5cf20607d60 EFLAGS: 00010246 [ 1987.244423] RAX: 000000000000005f RBX:
    000000000000001f RCX: 0000000000000000 [ 1987.252480] RDX: 0000000000000000 RSI: ffffffff9c61429e RDI:
    00000000ffffffff [ 1987.260538] RBP: ff62f5cf20607d78 R08: ff2a6a89ef3fffe8 R09: 00000000fffeffff [
    1987.268595] R10: ff2a6a89eed00000 R11: 0000000000000003 R12: ff2a66934849c89a [ 1987.276652] R13:
    0000000000000001 R14: ff2a66934849c8b9 R15: ff2a66934849c899 [ 1987.284710] FS: 0000000000000000(0000)
    GS:ff2a66b22fe40000(0000) knlGS:0000000000000000 [ 1987.293850] CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 [ 1987.300355] CR2: 00007fe291a37000 CR3: 000000010fbd4005 CR4: 0000000000f71ef0 [
    1987.308413] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [ 1987.316470] DR3:
    0000000000000000 DR6: 00000000fffe07f0 DR7: 0000000000000400 [ 1987.324527] PKRU: 55555554 [ 1987.327622]
    Call Trace: [ 1987.330424] <TASK> [ 1987.332826] ? show_regs+0x6e/0x80 [ 1987.336703] ? die+0x3c/0xa0 [
    1987.339988] ? do_trap+0xd4/0xf0 [ 1987.343662] ? do_error_trap+0x75/0xa0 [ 1987.347922] ?
    usercopy_abort+0x72/0x90 [ 1987.352277] ? exc_invalid_op+0x57/0x80 [ 1987.356634] ?
    usercopy_abort+0x72/0x90 [ 1987.360988] ? asm_exc_invalid_op+0x1f/0x30 [ 1987.365734] ?
    usercopy_abort+0x72/0x90 [ 1987.370088] __check_heap_object+0xb7/0xd0 [ 1987.374739]
    __check_object_size+0x175/0x2d0 [ 1987.379588] idxd_copy_cr+0xa9/0x130 [idxd] [ 1987.384341]
    idxd_evl_fault_work+0x127/0x390 [idxd] [ 1987.389878] process_one_work+0x13e/0x300 [ 1987.394435] ?
    __pfx_worker_thread+0x10/0x10 [ 1987.399284] worker_thread+0x2f7/0x420 [ 1987.403544] ?
    _raw_spin_unlock_irqrestore+0x2b/0x50 [ 1987.409171] ? __pfx_worker_thread+0x10/0x10 [ 1987.414019]
    kthread+0x107/0x140 [ 1987.417693] ? __pfx_kthread+0x10/0x10 [ 1987.421954] ret_from_fork+0x3d/0x60 [
    1987.426019] ? __pfx_kthread+0x10/0x10 [ 1987.430281] ret_from_fork_asm+0x1b/0x30 [ 1987.434744] </TASK>
    The issue arises because event log cache is created using kmem_cache_create() which is not suitable for
    user copy. Fix the issue by creating event log cache with kmem_cache_create_usercopy(), ensuring safe user
    copy. (CVE-2024-26746)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/04");
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
