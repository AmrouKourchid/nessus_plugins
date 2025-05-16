#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229467);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-43910");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-43910");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bpf: add missing
    check_func_arg_reg_off() to prevent out-of-bounds memory accesses Currently, it's possible to pass in a
    modified CONST_PTR_TO_DYNPTR to a global function as an argument. The adverse effects of this is that BPF
    helpers can continue to make use of this modified CONST_PTR_TO_DYNPTR from within the context of the
    global function, which can unintentionally result in out-of-bounds memory accesses and therefore
    compromise overall system stability i.e. [ 244.157771] BUG: KASAN: slab-out-of-bounds in
    bpf_dynptr_data+0x137/0x140 [ 244.161345] Read of size 8 at addr ffff88810914be68 by task test_progs/302 [
    244.167151] CPU: 0 PID: 302 Comm: test_progs Tainted: G O E 6.10.0-rc3-00131-g66b586715063 #533 [
    244.174318] Call Trace: [ 244.175787] <TASK> [ 244.177356] dump_stack_lvl+0x66/0xa0 [ 244.179531]
    print_report+0xce/0x670 [ 244.182314] ? __virt_addr_valid+0x200/0x3e0 [ 244.184908]
    kasan_report+0xd7/0x110 [ 244.187408] ? bpf_dynptr_data+0x137/0x140 [ 244.189714] ?
    bpf_dynptr_data+0x137/0x140 [ 244.192020] bpf_dynptr_data+0x137/0x140 [ 244.194264]
    bpf_prog_b02a02fdd2bdc5fa_global_call_bpf_dynptr_data+0x22/0x26 [ 244.198044]
    bpf_prog_b0fe7b9d7dc3abde_callback_adjust_bpf_dynptr_reg_off+0x1f/0x23 [ 244.202136]
    bpf_user_ringbuf_drain+0x2c7/0x570 [ 244.204744] ? 0xffffffffc0009e58 [ 244.206593] ?
    __pfx_bpf_user_ringbuf_drain+0x10/0x10 [ 244.209795]
    bpf_prog_33ab33f6a804ba2d_user_ringbuf_callback_const_ptr_to_dynptr_reg_off+0x47/0x4b [ 244.215922]
    bpf_trampoline_6442502480+0x43/0xe3 [ 244.218691] __x64_sys_prlimit64+0x9/0xf0 [ 244.220912]
    do_syscall_64+0xc1/0x1d0 [ 244.223043] entry_SYSCALL_64_after_hwframe+0x77/0x7f [ 244.226458] RIP:
    0033:0x7ffa3eb8f059 [ 244.228582] Code: 08 89 e8 5b 5d c3 66 2e 0f 1f 84 00 00 00 00 00 90 48 89 f8 48 89
    f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 8f 1d 0d
    00 f7 d8 64 89 01 48 [ 244.241307] RSP: 002b:00007ffa3e9c6eb8 EFLAGS: 00000206 ORIG_RAX: 000000000000012e
    [ 244.246474] RAX: ffffffffffffffda RBX: 00007ffa3e9c7cdc RCX: 00007ffa3eb8f059 [ 244.250478] RDX:
    00007ffa3eb162b4 RSI: 0000000000000000 RDI: 00007ffa3e9c7fb0 [ 244.255396] RBP: 00007ffa3e9c6ed0 R08:
    00007ffa3e9c76c0 R09: 0000000000000000 [ 244.260195] R10: 0000000000000000 R11: 0000000000000206 R12:
    ffffffffffffff80 [ 244.264201] R13: 000000000000001c R14: 00007ffc5d6b4260 R15: 00007ffa3e1c7000 [
    244.268303] </TASK> Add a check_func_arg_reg_off() to the path in which the BPF verifier verifies the
    arguments of global function arguments, specifically those which take an argument of type
    ARG_PTR_TO_DYNPTR | MEM_RDONLY. Also, process_dynptr_func() doesn't appear to perform any explicit and
    strict type matching on the supplied register type, so let's also enforce that a register either type
    PTR_TO_STACK or CONST_PTR_TO_DYNPTR is by the caller. (CVE-2024-43910)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43910");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/26");
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
