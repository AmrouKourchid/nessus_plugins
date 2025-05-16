#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224363);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47376");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47376");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Add oversize check before call
    kvcalloc() Commit 7661809d493b (mm: don't allow oversized kvmalloc() calls) add the oversize check. When
    the allocation is larger than what kmalloc() supports, the following warning triggered: WARNING: CPU: 0
    PID: 8408 at mm/util.c:597 kvmalloc_node+0x108/0x110 mm/util.c:597 Modules linked in: CPU: 0 PID: 8408
    Comm: syz-executor221 Not tainted 5.14.0-syzkaller #0 Hardware name: Google Google Compute Engine/Google
    Compute Engine, BIOS Google 01/01/2011 RIP: 0010:kvmalloc_node+0x108/0x110 mm/util.c:597 Call Trace:
    kvmalloc include/linux/mm.h:806 [inline] kvmalloc_array include/linux/mm.h:824 [inline] kvcalloc
    include/linux/mm.h:829 [inline] check_btf_line kernel/bpf/verifier.c:9925 [inline] check_btf_info
    kernel/bpf/verifier.c:10049 [inline] bpf_check+0xd634/0x150d0 kernel/bpf/verifier.c:13759 bpf_prog_load
    kernel/bpf/syscall.c:2301 [inline] __sys_bpf+0x11181/0x126e0 kernel/bpf/syscall.c:4587 __do_sys_bpf
    kernel/bpf/syscall.c:4691 [inline] __se_sys_bpf kernel/bpf/syscall.c:4689 [inline] __x64_sys_bpf+0x78/0x90
    kernel/bpf/syscall.c:4689 do_syscall_x64 arch/x86/entry/common.c:50 [inline] do_syscall_64+0x3d/0xb0
    arch/x86/entry/common.c:80 entry_SYSCALL_64_after_hwframe+0x44/0xae (CVE-2021-47376)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47376");

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
