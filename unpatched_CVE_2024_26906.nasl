#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227822);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26906");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26906");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: x86/mm: Disallow vsyscall page read
    for copy_from_kernel_nofault() When trying to use copy_from_kernel_nofault() to read vsyscall page through
    a bpf program, the following oops was reported: BUG: unable to handle page fault for address:
    ffffffffff600000 #PF: supervisor read access in kernel mode #PF: error_code(0x0000) - not-present page PGD
    3231067 P4D 3231067 PUD 3233067 PMD 3235067 PTE 0 Oops: 0000 [#1] PREEMPT SMP PTI CPU: 1 PID: 20390 Comm:
    test_progs ...... 6.7.0+ #58 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996) ...... RIP:
    0010:copy_from_kernel_nofault+0x6f/0x110 ...... Call Trace: <TASK> ? copy_from_kernel_nofault+0x6f/0x110
    bpf_probe_read_kernel+0x1d/0x50 bpf_prog_2061065e56845f08_do_probe_read+0x51/0x8d
    trace_call_bpf+0xc5/0x1c0 perf_call_bpf_enter.isra.0+0x69/0xb0 perf_syscall_enter+0x13e/0x200
    syscall_trace_enter+0x188/0x1c0 do_syscall_64+0xb5/0xe0 entry_SYSCALL_64_after_hwframe+0x6e/0x76 </TASK>
    ...... ---[ end trace 0000000000000000 ]--- The oops is triggered when: 1) A bpf program uses
    bpf_probe_read_kernel() to read from the vsyscall page and invokes copy_from_kernel_nofault() which in
    turn calls __get_user_asm(). 2) Because the vsyscall page address is not readable from kernel space, a
    page fault exception is triggered accordingly. 3) handle_page_fault() considers the vsyscall page address
    as a user space address instead of a kernel space address. This results in the fix-up setup by bpf not
    being applied and a page_fault_oops() is invoked due to SMAP. Considering handle_page_fault() has already
    considered the vsyscall page address as a userspace address, fix the problem by disallowing vsyscall page
    read for copy_from_kernel_nofault(). (CVE-2024-26906)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26906");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

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
    "name": [
     "linux-azure-cloud-tools-5.4.0-1010",
     "linux-azure-fips",
     "linux-azure-headers-5.4.0-1010",
     "linux-azure-tools-5.4.0-1010",
     "linux-buildinfo-5.4.0-1010-azure",
     "linux-cloud-tools-5.4.0-1010-azure",
     "linux-headers-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure-dbgsym",
     "linux-modules-5.4.0-1010-azure",
     "linux-modules-extra-5.4.0-1010-azure",
     "linux-tools-5.4.0-1010-azure",
     "linux-udebs-azure"
    ],
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
        "os_version": "20.04"
       }
      }
     ]
    }
   ]
  },
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
