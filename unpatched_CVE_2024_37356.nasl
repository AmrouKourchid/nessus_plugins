#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228925);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-37356");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-37356");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tcp: Fix shift-out-of-bounds in
    dctcp_update_alpha(). In dctcp_update_alpha(), we use a module parameter dctcp_shift_g as follows: alpha
    -= min_not_zero(alpha, alpha >> dctcp_shift_g); ... delivered_ce <<= (10 - dctcp_shift_g); It seems
    syzkaller started fuzzing module parameters and triggered shift-out-of-bounds [0] by setting 100 to
    dctcp_shift_g: memcpy((void*)0x20000080, /sys/module/tcp_dctcp/parameters/dctcp_shift_g\000, 47); res =
    syscall(__NR_openat, /*fd=*/0xffffffffffffff9cul, /*file=*/0x20000080ul, /*flags=*/2ul, /*mode=*/0ul);
    memcpy((void*)0x20000000, 100\000, 4); syscall(__NR_write, /*fd=*/r[0], /*val=*/0x20000000ul,
    /*len=*/4ul); Let's limit the max value of dctcp_shift_g by param_set_uint_minmax(). With this patch: #
    echo 10 > /sys/module/tcp_dctcp/parameters/dctcp_shift_g # cat
    /sys/module/tcp_dctcp/parameters/dctcp_shift_g 10 # echo 11 >
    /sys/module/tcp_dctcp/parameters/dctcp_shift_g -bash: echo: write error: Invalid argument [0]: UBSAN:
    shift-out-of-bounds in net/ipv4/tcp_dctcp.c:143:12 shift exponent 100 is too large for 32-bit type 'u32'
    (aka 'unsigned int') CPU: 0 PID: 8083 Comm: syz-executor345 Not tainted 6.9.0-05151-g1b294a1f3561 #2
    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014 Call Trace:
    <TASK> __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0x201/0x300 lib/dump_stack.c:114
    ubsan_epilogue lib/ubsan.c:231 [inline] __ubsan_handle_shift_out_of_bounds+0x346/0x3a0 lib/ubsan.c:468
    dctcp_update_alpha+0x540/0x570 net/ipv4/tcp_dctcp.c:143 tcp_in_ack_event net/ipv4/tcp_input.c:3802
    [inline] tcp_ack+0x17b1/0x3bc0 net/ipv4/tcp_input.c:3948 tcp_rcv_state_process+0x57a/0x2290
    net/ipv4/tcp_input.c:6711 tcp_v4_do_rcv+0x764/0xc40 net/ipv4/tcp_ipv4.c:1937 sk_backlog_rcv
    include/net/sock.h:1106 [inline] __release_sock+0x20f/0x350 net/core/sock.c:2983 release_sock+0x61/0x1f0
    net/core/sock.c:3549 mptcp_subflow_shutdown+0x3d0/0x620 net/mptcp/protocol.c:2907
    mptcp_check_send_data_fin+0x225/0x410 net/mptcp/protocol.c:2976 __mptcp_close+0x238/0xad0
    net/mptcp/protocol.c:3072 mptcp_close+0x2a/0x1a0 net/mptcp/protocol.c:3127 inet_release+0x190/0x1f0
    net/ipv4/af_inet.c:437 __sock_release net/socket.c:659 [inline] sock_close+0xc0/0x240 net/socket.c:1421
    __fput+0x41b/0x890 fs/file_table.c:422 task_work_run+0x23b/0x300 kernel/task_work.c:180 exit_task_work
    include/linux/task_work.h:38 [inline] do_exit+0x9c8/0x2540 kernel/exit.c:878 do_group_exit+0x201/0x2b0
    kernel/exit.c:1027 __do_sys_exit_group kernel/exit.c:1038 [inline] __se_sys_exit_group kernel/exit.c:1036
    [inline] __x64_sys_exit_group+0x3f/0x40 kernel/exit.c:1036 do_syscall_x64 arch/x86/entry/common.c:52
    [inline] do_syscall_64+0xe4/0x240 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x67/0x6f RIP:
    0033:0x7f6c2b5005b6 Code: Unable to access opcode bytes at 0x7f6c2b50058c. RSP: 002b:00007ffe883eb948
    EFLAGS: 00000246 ORIG_RAX: 00000000000000e7 RAX: ffffffffffffffda RBX: 00007f6c2b5862f0 RCX:
    00007f6c2b5005b6 RDX: 0000000000000001 RSI: 000000000000003c RDI: 0000000000000001 RBP: 0000000000000001
    R08: 00000000000000e7 R09: ffffffffffffffc0 R10: 0000000000000006 R11: 0000000000000246 R12:
    00007f6c2b5862f0 R13: 0000000000000001 R14: 0000000000000000 R15: 0000000000000001 </TASK>
    (CVE-2024-37356)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37356");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/21");
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
