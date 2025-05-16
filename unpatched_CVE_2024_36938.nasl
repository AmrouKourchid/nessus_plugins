#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229286);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36938");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36938");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bpf, skmsg: Fix NULL pointer
    dereference in sk_psock_skb_ingress_enqueue Fix NULL pointer data-races in sk_psock_skb_ingress_enqueue()
    which syzbot reported [1]. [1] BUG: KCSAN: data-race in sk_psock_drop / sk_psock_skb_ingress_enqueue write
    to 0xffff88814b3278b8 of 8 bytes by task 10724 on cpu 1: sk_psock_stop_verdict net/core/skmsg.c:1257
    [inline] sk_psock_drop+0x13e/0x1f0 net/core/skmsg.c:843 sk_psock_put include/linux/skmsg.h:459 [inline]
    sock_map_close+0x1a7/0x260 net/core/sock_map.c:1648 unix_release+0x4b/0x80 net/unix/af_unix.c:1048
    __sock_release net/socket.c:659 [inline] sock_close+0x68/0x150 net/socket.c:1421 __fput+0x2c1/0x660
    fs/file_table.c:422 __fput_sync+0x44/0x60 fs/file_table.c:507 __do_sys_close fs/open.c:1556 [inline]
    __se_sys_close+0x101/0x1b0 fs/open.c:1541 __x64_sys_close+0x1f/0x30 fs/open.c:1541
    do_syscall_64+0xd3/0x1d0 entry_SYSCALL_64_after_hwframe+0x6d/0x75 read to 0xffff88814b3278b8 of 8 bytes by
    task 10713 on cpu 0: sk_psock_data_ready include/linux/skmsg.h:464 [inline]
    sk_psock_skb_ingress_enqueue+0x32d/0x390 net/core/skmsg.c:555 sk_psock_skb_ingress_self+0x185/0x1e0
    net/core/skmsg.c:606 sk_psock_verdict_apply net/core/skmsg.c:1008 [inline]
    sk_psock_verdict_recv+0x3e4/0x4a0 net/core/skmsg.c:1202 unix_read_skb net/unix/af_unix.c:2546 [inline]
    unix_stream_read_skb+0x9e/0xf0 net/unix/af_unix.c:2682 sk_psock_verdict_data_ready+0x77/0x220
    net/core/skmsg.c:1223 unix_stream_sendmsg+0x527/0x860 net/unix/af_unix.c:2339 sock_sendmsg_nosec
    net/socket.c:730 [inline] __sock_sendmsg+0x140/0x180 net/socket.c:745 ____sys_sendmsg+0x312/0x410
    net/socket.c:2584 ___sys_sendmsg net/socket.c:2638 [inline] __sys_sendmsg+0x1e9/0x280 net/socket.c:2667
    __do_sys_sendmsg net/socket.c:2676 [inline] __se_sys_sendmsg net/socket.c:2674 [inline]
    __x64_sys_sendmsg+0x46/0x50 net/socket.c:2674 do_syscall_64+0xd3/0x1d0
    entry_SYSCALL_64_after_hwframe+0x6d/0x75 value changed: 0xffffffff83d7feb0 -> 0x0000000000000000 Reported
    by Kernel Concurrency Sanitizer on: CPU: 0 PID: 10713 Comm: syz-executor.4 Tainted: G W
    6.8.0-syzkaller-08951-gfe46a7dd189e #0 Hardware name: Google Google Compute Engine/Google Compute Engine,
    BIOS Google 02/29/2024 Prior to this, commit 4cd12c6065df (bpf, sockmap: Fix NULL pointer dereference in
    sk_psock_verdict_data_ready()) fixed one NULL pointer similarly due to no protection of saved_data_ready.
    Here is another different caller causing the same issue because of the same reason. So we should protect
    it with sk_callback_lock read lock because the writer side in the sk_psock_drop() uses
    write_lock_bh(&sk->sk_callback_lock);. To avoid errors that could happen in future, I move those two
    pairs of lock into the sk_psock_data_ready(), which is suggested by John Fastabend. (CVE-2024-36938)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36938");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
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
    "name": "linux-gkeop",
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
    "name": "kernel",
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
