#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227448);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26638");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26638");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: nbd: always initialize struct msghdr
    completely syzbot complains that msg->msg_get_inq value can be uninitialized [1] struct msghdr got many
    new fields recently, we should always make sure their values is zero by default. [1] BUG: KMSAN: uninit-
    value in tcp_recvmsg+0x686/0xac0 net/ipv4/tcp.c:2571 tcp_recvmsg+0x686/0xac0 net/ipv4/tcp.c:2571
    inet_recvmsg+0x131/0x580 net/ipv4/af_inet.c:879 sock_recvmsg_nosec net/socket.c:1044 [inline]
    sock_recvmsg+0x12b/0x1e0 net/socket.c:1066 __sock_xmit+0x236/0x5c0 drivers/block/nbd.c:538 nbd_read_reply
    drivers/block/nbd.c:732 [inline] recv_work+0x262/0x3100 drivers/block/nbd.c:863 process_one_work
    kernel/workqueue.c:2627 [inline] process_scheduled_works+0x104e/0x1e70 kernel/workqueue.c:2700
    worker_thread+0xf45/0x1490 kernel/workqueue.c:2781 kthread+0x3ed/0x540 kernel/kthread.c:388
    ret_from_fork+0x66/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x11/0x20
    arch/x86/entry/entry_64.S:242 Local variable msg created at: __sock_xmit+0x4c/0x5c0
    drivers/block/nbd.c:513 nbd_read_reply drivers/block/nbd.c:732 [inline] recv_work+0x262/0x3100
    drivers/block/nbd.c:863 CPU: 1 PID: 7465 Comm: kworker/u5:1 Not tainted
    6.7.0-rc7-syzkaller-00041-gf016f7547aee #0 Hardware name: Google Google Compute Engine/Google Compute
    Engine, BIOS Google 11/17/2023 Workqueue: nbd5-recv recv_work (CVE-2024-26638)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26638");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
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
