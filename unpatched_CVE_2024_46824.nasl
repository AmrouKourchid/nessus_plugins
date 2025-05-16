#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229402);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-46824");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-46824");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: iommufd: Require drivers to supply the
    cache_invalidate_user ops If drivers don't do this then iommufd will oops invalidation ioctls with
    something like: Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000 Mem
    abort info: ESR = 0x0000000086000004 EC = 0x21: IABT (current EL), IL = 32 bits SET = 0, FnV = 0 EA = 0,
    S1PTW = 0 FSC = 0x04: level 0 translation fault user pgtable: 4k pages, 48-bit VAs, pgdp=0000000101059000
    [0000000000000000] pgd=0000000000000000, p4d=0000000000000000 Internal error: Oops: 0000000086000004 [#1]
    PREEMPT SMP Modules linked in: CPU: 2 PID: 371 Comm: qemu-system-aar Not tainted 6.8.0-rc7-gde77230ac23a
    #9 Hardware name: linux,dummy-virt (DT) pstate: 81400809 (Nzcv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=-c) pc
    : 0x0 lr : iommufd_hwpt_invalidate+0xa4/0x204 sp : ffff800080f3bcc0 x29: ffff800080f3bcf0 x28:
    ffff0000c369b300 x27: 0000000000000000 x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
    x23: 0000000000000000 x22: 00000000c1e334a0 x21: ffff0000c1e334a0 x20: ffff800080f3bd38 x19:
    ffff800080f3bd58 x18: 0000000000000000 x17: 0000000000000000 x16: 0000000000000000 x15: 0000ffff8240d6d8
    x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000 x11: 0000000000000000 x10:
    0000000000000000 x9 : 0000000000000000 x8 : 0000001000000002 x7 : 0000fffeac1ec950 x6 : 0000000000000000
    x5 : ffff800080f3bd78 x4 : 0000000000000003 x3 : 0000000000000002 x2 : 0000000000000000 x1 :
    ffff800080f3bcc8 x0 : ffff0000c6034d80 Call trace: 0x0 iommufd_fops_ioctl+0x154/0x274
    __arm64_sys_ioctl+0xac/0xf0 invoke_syscall+0x48/0x110 el0_svc_common.constprop.0+0x40/0xe0
    do_el0_svc+0x1c/0x28 el0_svc+0x34/0xb4 el0t_64_sync_handler+0x120/0x12c el0t_64_sync+0x190/0x194 All
    existing drivers implement this op for nesting, this is mostly a bisection aid. (CVE-2024-46824)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46824");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/27");
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
