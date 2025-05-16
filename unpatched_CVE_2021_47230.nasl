#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230107);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47230");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47230");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: x86: Immediately reset the MMU
    context when the SMM flag is cleared Immediately reset the MMU context when the vCPU's SMM flag is cleared
    so that the SMM flag in the MMU role is always synchronized with the vCPU's flag. If RSM fails (which
    isn't correctly emulated), KVM will bail without calling post_leave_smm() and leave the MMU in a bad
    state. The bad MMU role can lead to a NULL pointer dereference when grabbing a shadow page's rmap for a
    page fault as the initial lookups for the gfn will happen with the vCPU's SMM flag (=0), whereas the rmap
    lookup will use the shadow page's SMM flag, which comes from the MMU (=1). SMM has an entirely different
    set of memslots, and so the initial lookup can find a memslot (SMM=0) and then explode on the rmap memslot
    lookup (SMM=1). general protection fault, probably for non-canonical address 0xdffffc0000000000: 0000 [#1]
    PREEMPT SMP KASAN KASAN: null-ptr-deref in range [0x0000000000000000-0x0000000000000007] CPU: 1 PID: 8410
    Comm: syz-executor382 Not tainted 5.13.0-rc5-syzkaller #0 Hardware name: Google Google Compute
    Engine/Google Compute Engine, BIOS Google 01/01/2011 RIP: 0010:__gfn_to_rmap arch/x86/kvm/mmu/mmu.c:935
    [inline] RIP: 0010:gfn_to_rmap+0x2b0/0x4d0 arch/x86/kvm/mmu/mmu.c:947 Code: <42> 80 3c 20 00 74 08 4c 89
    ff e8 f1 79 a9 00 4c 89 fb 4d 8b 37 44 RSP: 0018:ffffc90000ffef98 EFLAGS: 00010246 RAX: 0000000000000000
    RBX: ffff888015b9f414 RCX: ffff888019669c40 RDX: 0000000000000000 RSI: 0000000000000001 RDI:
    0000000000000001 RBP: 0000000000000001 R08: ffffffff811d9cdb R09: ffffed10065a6002 R10: ffffed10065a6002
    R11: 0000000000000000 R12: dffffc0000000000 R13: 0000000000000003 R14: 0000000000000001 R15:
    0000000000000000 FS: 000000000124b300(0000) GS:ffff8880b9b00000(0000) knlGS:0000000000000000 CS: 0010 DS:
    0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000000000000 CR3: 0000000028e31000 CR4: 00000000001526e0 DR0:
    0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0
    DR7: 0000000000000400 Call Trace: rmap_add arch/x86/kvm/mmu/mmu.c:965 [inline] mmu_set_spte+0x862/0xe60
    arch/x86/kvm/mmu/mmu.c:2604 __direct_map arch/x86/kvm/mmu/mmu.c:2862 [inline]
    direct_page_fault+0x1f74/0x2b70 arch/x86/kvm/mmu/mmu.c:3769 kvm_mmu_do_page_fault arch/x86/kvm/mmu.h:124
    [inline] kvm_mmu_page_fault+0x199/0x1440 arch/x86/kvm/mmu/mmu.c:5065 vmx_handle_exit+0x26/0x160
    arch/x86/kvm/vmx/vmx.c:6122 vcpu_enter_guest+0x3bdd/0x9630 arch/x86/kvm/x86.c:9428 vcpu_run+0x416/0xc20
    arch/x86/kvm/x86.c:9494 kvm_arch_vcpu_ioctl_run+0x4e8/0xa40 arch/x86/kvm/x86.c:9722
    kvm_vcpu_ioctl+0x70f/0xbb0 arch/x86/kvm/../../../virt/kvm/kvm_main.c:3460 vfs_ioctl fs/ioctl.c:51 [inline]
    __do_sys_ioctl fs/ioctl.c:1069 [inline] __se_sys_ioctl+0xfb/0x170 fs/ioctl.c:1055 do_syscall_64+0x3f/0xb0
    arch/x86/entry/common.c:47 entry_SYSCALL_64_after_hwframe+0x44/0xae RIP: 0033:0x440ce9 (CVE-2021-47230)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47230");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
