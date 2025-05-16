#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228918);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-38596");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-38596");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: af_unix: Fix data races in
    unix_release_sock/unix_stream_sendmsg A data-race condition has been identified in af_unix. In one data
    path, the write function unix_release_sock() atomically writes to sk->sk_shutdown using WRITE_ONCE.
    However, on the reader side, unix_stream_sendmsg() does not read it atomically. Consequently, this issue
    is causing the following KCSAN splat to occur: BUG: KCSAN: data-race in unix_release_sock /
    unix_stream_sendmsg write (marked) to 0xffff88867256ddbb of 1 bytes by task 7270 on cpu 28:
    unix_release_sock (net/unix/af_unix.c:640) unix_release (net/unix/af_unix.c:1050) sock_close
    (net/socket.c:659 net/socket.c:1421) __fput (fs/file_table.c:422) __fput_sync (fs/file_table.c:508)
    __se_sys_close (fs/open.c:1559 fs/open.c:1541) __x64_sys_close (fs/open.c:1541) x64_sys_call
    (arch/x86/entry/syscall_64.c:33) do_syscall_64 (arch/x86/entry/common.c:?) entry_SYSCALL_64_after_hwframe
    (arch/x86/entry/entry_64.S:130) read to 0xffff88867256ddbb of 1 bytes by task 989 on cpu 14:
    unix_stream_sendmsg (net/unix/af_unix.c:2273) __sock_sendmsg (net/socket.c:730 net/socket.c:745)
    ____sys_sendmsg (net/socket.c:2584) __sys_sendmmsg (net/socket.c:2638 net/socket.c:2724)
    __x64_sys_sendmmsg (net/socket.c:2753 net/socket.c:2750 net/socket.c:2750) x64_sys_call
    (arch/x86/entry/syscall_64.c:33) do_syscall_64 (arch/x86/entry/common.c:?) entry_SYSCALL_64_after_hwframe
    (arch/x86/entry/entry_64.S:130) value changed: 0x01 -> 0x03 The line numbers are related to commit
    dd5a440a31fa (Linux 6.9-rc7). Commit e1d09c2c2f57 (af_unix: Fix data races around sk->sk_shutdown.)
    addressed a comparable issue in the past regarding sk->sk_shutdown. However, it overlooked resolving this
    particular data path. This patch only offending unix_stream_sendmsg() function, since the other reads seem
    to be protected by unix_state_lock() as discussed in (CVE-2024-38596)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38596");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/19");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
