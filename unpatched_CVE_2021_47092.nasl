#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224394);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47092");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47092");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: VMX: Always clear vmx->fail on
    emulation_required Revert a relatively recent change that set vmx->fail if the vCPU is in L2 and
    emulation_required is true, as that behavior is completely bogus. Setting vmx->fail and synthesizing a VM-
    Exit is contradictory and wrong: (a) it's impossible to have both a VM-Fail and VM-Exit (b)
    vmcs.EXIT_REASON is not modified on VM-Fail (c) emulation_required refers to guest state and guest state
    checks are always VM-Exits, not VM-Fails. For KVM specifically, emulation_required is handled before
    nested exits in __vmx_handle_exit(), thus setting vmx->fail has no immediate effect, i.e. KVM calls into
    handle_invalid_guest_state() and vmx->fail is ignored. Setting vmx->fail can ultimately result in a WARN
    in nested_vmx_vmexit() firing when tearing down the VM as KVM never expects vmx->fail to be set when L2 is
    active, KVM always reflects those errors into L1. ------------[ cut here ]------------ WARNING: CPU: 0
    PID: 21158 at arch/x86/kvm/vmx/nested.c:4548 nested_vmx_vmexit+0x16bd/0x17e0
    arch/x86/kvm/vmx/nested.c:4547 Modules linked in: CPU: 0 PID: 21158 Comm: syz-executor.1 Not tainted
    5.16.0-rc3-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google
    01/01/2011 RIP: 0010:nested_vmx_vmexit+0x16bd/0x17e0 arch/x86/kvm/vmx/nested.c:4547 Code: <0f> 0b e9 2e f8
    ff ff e8 57 b3 5d 00 0f 0b e9 00 f1 ff ff 89 e9 80 Call Trace: vmx_leave_nested
    arch/x86/kvm/vmx/nested.c:6220 [inline] nested_vmx_free_vcpu+0x83/0xc0 arch/x86/kvm/vmx/nested.c:330
    vmx_free_vcpu+0x11f/0x2a0 arch/x86/kvm/vmx/vmx.c:6799 kvm_arch_vcpu_destroy+0x6b/0x240
    arch/x86/kvm/x86.c:10989 kvm_vcpu_destroy+0x29/0x90 arch/x86/kvm/../../../virt/kvm/kvm_main.c:441
    kvm_free_vcpus arch/x86/kvm/x86.c:11426 [inline] kvm_arch_destroy_vm+0x3ef/0x6b0 arch/x86/kvm/x86.c:11545
    kvm_destroy_vm arch/x86/kvm/../../../virt/kvm/kvm_main.c:1189 [inline] kvm_put_kvm+0x751/0xe40
    arch/x86/kvm/../../../virt/kvm/kvm_main.c:1220 kvm_vcpu_release+0x53/0x60
    arch/x86/kvm/../../../virt/kvm/kvm_main.c:3489 __fput+0x3fc/0x870 fs/file_table.c:280
    task_work_run+0x146/0x1c0 kernel/task_work.c:164 exit_task_work include/linux/task_work.h:32 [inline]
    do_exit+0x705/0x24f0 kernel/exit.c:832 do_group_exit+0x168/0x2d0 kernel/exit.c:929
    get_signal+0x1740/0x2120 kernel/signal.c:2852 arch_do_signal_or_restart+0x9c/0x730
    arch/x86/kernel/signal.c:868 handle_signal_work kernel/entry/common.c:148 [inline] exit_to_user_mode_loop
    kernel/entry/common.c:172 [inline] exit_to_user_mode_prepare+0x191/0x220 kernel/entry/common.c:207
    __syscall_exit_to_user_mode_work kernel/entry/common.c:289 [inline] syscall_exit_to_user_mode+0x2e/0x70
    kernel/entry/common.c:300 do_syscall_64+0x53/0xd0 arch/x86/entry/common.c:86
    entry_SYSCALL_64_after_hwframe+0x44/0xae (CVE-2021-47092)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47092");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/04");
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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
