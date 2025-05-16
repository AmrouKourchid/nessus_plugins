#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230181);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47262");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47262");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: x86: Ensure liveliness of nested
    VM-Enter fail tracepoint message Use the __string() machinery provided by the tracing subystem to make a
    copy of the string literals consumed by the nested VM-Enter failed tracepoint. A complete copy is
    necessary to ensure that the tracepoint can't outlive the data/memory it consumes and deference stale
    memory. Because the tracepoint itself is defined by kvm, if kvm-intel and/or kvm-amd are built as modules,
    the memory holding the string literals defined by the vendor modules will be freed when the module is
    unloaded, whereas the tracepoint and its data in the ring buffer will live until kvm is unloaded (or
    indefinitely if kvm is built-in). This bug has existed since the tracepoint was added, but was recently
    exposed by a new check in tracing to detect exactly this type of bug. fmt: '%s%s ' current_buffer: '
    vmx_dirty_log_t-140127 [003] .... kvm_nested_vmenter_failed: ' WARNING: CPU: 3 PID: 140134 at
    kernel/trace/trace.c:3759 trace_check_vprintf+0x3be/0x3e0 CPU: 3 PID: 140134 Comm: less Not tainted
    5.13.0-rc1-ce2e73ce600a-req #184 Hardware name: ASUS Q87M-E/Q87M-E, BIOS 1102 03/03/2014 RIP:
    0010:trace_check_vprintf+0x3be/0x3e0 Code: <0f> 0b 44 8b 4c 24 1c e9 a9 fe ff ff c6 44 02 ff 00 49 8b 97
    b0 20 RSP: 0018:ffffa895cc37bcb0 EFLAGS: 00010282 RAX: 0000000000000000 RBX: ffffa895cc37bd08 RCX:
    0000000000000027 RDX: 0000000000000027 RSI: 00000000ffffdfff RDI: ffff9766cfad74f8 RBP: ffffffffc0a041d4
    R08: ffff9766cfad74f0 R09: ffffa895cc37bad8 R10: 0000000000000001 R11: 0000000000000001 R12:
    ffffffffc0a041d4 R13: ffffffffc0f4dba8 R14: 0000000000000000 R15: ffff976409f2c000 FS:
    00007f92fa200740(0000) GS:ffff9766cfac0000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 CR2: 0000559bd11b0000 CR3: 000000019fbaa002 CR4: 00000000001726e0 Call Trace:
    trace_event_printf+0x5e/0x80 trace_raw_output_kvm_nested_vmenter_failed+0x3a/0x60 [kvm]
    print_trace_line+0x1dd/0x4e0 s_show+0x45/0x150 seq_read_iter+0x2d5/0x4c0 seq_read+0x106/0x150
    vfs_read+0x98/0x180 ksys_read+0x5f/0xe0 do_syscall_64+0x40/0xb0 entry_SYSCALL_64_after_hwframe+0x44/0xae
    (CVE-2021-47262)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47262");

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
