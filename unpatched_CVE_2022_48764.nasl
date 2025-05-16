#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225621);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48764");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48764");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: x86: Free kvm_cpuid_entry2 array
    on post-KVM_RUN KVM_SET_CPUID{,2} Free the struct kvm_cpuid_entry2 array on successful post-KVM_RUN
    KVM_SET_CPUID{,2} to fix a memory leak, the callers of kvm_set_cpuid() free the array only on failure.
    BUG: memory leak unreferenced object 0xffff88810963a800 (size 2048): comm syz-executor025, pid 3610,
    jiffies 4294944928 (age 8.080s) hex dump (first 32 bytes): 00 00 00 00 00 00 00 00 00 00 00 00 0d 00 00 00
    ................ 47 65 6e 75 6e 74 65 6c 69 6e 65 49 00 00 00 00 GenuntelineI.... backtrace:
    [<ffffffff814948ee>] kmalloc_node include/linux/slab.h:604 [inline] [<ffffffff814948ee>]
    kvmalloc_node+0x3e/0x100 mm/util.c:580 [<ffffffff814950f2>] kvmalloc include/linux/slab.h:732 [inline]
    [<ffffffff814950f2>] vmemdup_user+0x22/0x100 mm/util.c:199 [<ffffffff8109f5ff>]
    kvm_vcpu_ioctl_set_cpuid2+0x8f/0xf0 arch/x86/kvm/cpuid.c:423 [<ffffffff810711b9>]
    kvm_arch_vcpu_ioctl+0xb99/0x1e60 arch/x86/kvm/x86.c:5251 [<ffffffff8103e92d>] kvm_vcpu_ioctl+0x4ad/0x950
    arch/x86/kvm/../../../virt/kvm/kvm_main.c:4066 [<ffffffff815afacc>] vfs_ioctl fs/ioctl.c:51 [inline]
    [<ffffffff815afacc>] __do_sys_ioctl fs/ioctl.c:874 [inline] [<ffffffff815afacc>] __se_sys_ioctl
    fs/ioctl.c:860 [inline] [<ffffffff815afacc>] __x64_sys_ioctl+0xfc/0x140 fs/ioctl.c:860
    [<ffffffff844a3335>] do_syscall_x64 arch/x86/entry/common.c:50 [inline] [<ffffffff844a3335>]
    do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80 [<ffffffff84600068>]
    entry_SYSCALL_64_after_hwframe+0x44/0xae (CVE-2022-48764)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48764");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/20");
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
