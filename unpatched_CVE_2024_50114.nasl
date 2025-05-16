#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230326);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-50114");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-50114");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: arm64: Unregister redistributor
    for failed vCPU creation Alex reports that syzkaller has managed to trigger a use-after-free when tearing
    down a VM: BUG: KASAN: slab-use-after-free in kvm_put_kvm+0x300/0xe68 virt/kvm/kvm_main.c:5769 Read of
    size 8 at addr ffffff801c6890d0 by task syz.3.2219/10758 CPU: 3 UID: 0 PID: 10758 Comm: syz.3.2219 Not
    tainted 6.11.0-rc6-dirty #64 Hardware name: linux,dummy-virt (DT) Call trace: dump_backtrace+0x17c/0x1a8
    arch/arm64/kernel/stacktrace.c:317 show_stack+0x2c/0x3c arch/arm64/kernel/stacktrace.c:324 __dump_stack
    lib/dump_stack.c:93 [inline] dump_stack_lvl+0x94/0xc0 lib/dump_stack.c:119 print_report+0x144/0x7a4
    mm/kasan/report.c:377 kasan_report+0xcc/0x128 mm/kasan/report.c:601 __asan_report_load8_noabort+0x20/0x2c
    mm/kasan/report_generic.c:381 kvm_put_kvm+0x300/0xe68 virt/kvm/kvm_main.c:5769 kvm_vm_release+0x4c/0x60
    virt/kvm/kvm_main.c:1409 __fput+0x198/0x71c fs/file_table.c:422 ____fput+0x20/0x30 fs/file_table.c:450
    task_work_run+0x1cc/0x23c kernel/task_work.c:228 do_notify_resume+0x144/0x1a0
    include/linux/resume_user_mode.h:50 el0_svc+0x64/0x68 arch/arm64/kernel/entry-common.c:169
    el0t_64_sync_handler+0x90/0xfc arch/arm64/kernel/entry-common.c:730 el0t_64_sync+0x190/0x194
    arch/arm64/kernel/entry.S:598 Upon closer inspection, it appears that we do not properly tear down the
    MMIO registration for a vCPU that fails creation late in the game, e.g. a vCPU w/ the same ID already
    exists in the VM. It is important to consider the context of commit that introduced this bug by moving the
    unregistration out of __kvm_vgic_vcpu_destroy(). That change correctly sought to avoid an srcu v.
    config_lock inversion by breaking up the vCPU teardown into two parts, one guarded by the config_lock. Fix
    the use-after-free while avoiding lock inversion by adding a special-cased unregistration to
    __kvm_vgic_vcpu_destroy(). This is safe because failed vCPUs are torn down outside of the config_lock.
    (CVE-2024-50114)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50114");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-lowlatency-hwe-6.11",
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
        "os_version": "24.04"
       }
      }
     ]
    }
   ]
  },
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
