#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224442);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47078");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47078");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: RDMA/rxe: Clear all QP fields if
    creation failed rxe_qp_do_cleanup() relies on valid pointer values in QP for the properly created ones,
    but in case rxe_qp_from_init() failed it was filled with garbage and caused tot the following error.
    refcount_t: underflow; use-after-free. WARNING: CPU: 1 PID: 12560 at lib/refcount.c:28
    refcount_warn_saturate+0x1d1/0x1e0 lib/refcount.c:28 Modules linked in: CPU: 1 PID: 12560 Comm: syz-
    executor.4 Not tainted 5.12.0-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute
    Engine, BIOS Google 01/01/2011 RIP: 0010:refcount_warn_saturate+0x1d1/0x1e0 lib/refcount.c:28 Code: e9 db
    fe ff ff 48 89 df e8 2c c2 ea fd e9 8a fe ff ff e8 72 6a a7 fd 48 c7 c7 e0 b2 c1 89 c6 05 dc 3a e6 09 01
    e8 ee 74 fb 04 <0f> 0b e9 af fe ff ff 0f 1f 84 00 00 00 00 00 41 56 41 55 41 54 55 RSP:
    0018:ffffc900097ceba8 EFLAGS: 00010286 RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000000
    RDX: 0000000000040000 RSI: ffffffff815bb075 RDI: fffff520012f9d67 RBP: 0000000000000003 R08:
    0000000000000000 R09: 0000000000000000 R10: ffffffff815b4eae R11: 0000000000000000 R12: ffff8880322a4800
    R13: ffff8880322a4940 R14: ffff888033044e00 R15: 0000000000000000 FS: 00007f6eb2be3700(0000)
    GS:ffff8880b9d00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007fdbe5d41000 CR3: 000000001d181000 CR4: 00000000001506e0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace:
    __refcount_sub_and_test include/linux/refcount.h:283 [inline] __refcount_dec_and_test
    include/linux/refcount.h:315 [inline] refcount_dec_and_test include/linux/refcount.h:333 [inline] kref_put
    include/linux/kref.h:64 [inline] rxe_qp_do_cleanup+0x96f/0xaf0 drivers/infiniband/sw/rxe/rxe_qp.c:805
    execute_in_process_context+0x37/0x150 kernel/workqueue.c:3327 rxe_elem_release+0x9f/0x180
    drivers/infiniband/sw/rxe/rxe_pool.c:391 kref_put include/linux/kref.h:65 [inline]
    rxe_create_qp+0x2cd/0x310 drivers/infiniband/sw/rxe/rxe_verbs.c:425 _ib_create_qp
    drivers/infiniband/core/core_priv.h:331 [inline] ib_create_named_qp+0x2ad/0x1370
    drivers/infiniband/core/verbs.c:1231 ib_create_qp include/rdma/ib_verbs.h:3644 [inline]
    create_mad_qp+0x177/0x2d0 drivers/infiniband/core/mad.c:2920 ib_mad_port_open
    drivers/infiniband/core/mad.c:3001 [inline] ib_mad_init_device+0xd6f/0x1400
    drivers/infiniband/core/mad.c:3092 add_client_context+0x405/0x5e0 drivers/infiniband/core/device.c:717
    enable_device_and_get+0x1cd/0x3b0 drivers/infiniband/core/device.c:1331 ib_register_device
    drivers/infiniband/core/device.c:1413 [inline] ib_register_device+0x7c7/0xa50
    drivers/infiniband/core/device.c:1365 rxe_register_device+0x3d5/0x4a0
    drivers/infiniband/sw/rxe/rxe_verbs.c:1147 rxe_add+0x12fe/0x16d0 drivers/infiniband/sw/rxe/rxe.c:247
    rxe_net_add+0x8c/0xe0 drivers/infiniband/sw/rxe/rxe_net.c:503 rxe_newlink
    drivers/infiniband/sw/rxe/rxe.c:269 [inline] rxe_newlink+0xb7/0xe0 drivers/infiniband/sw/rxe/rxe.c:250
    nldev_newlink+0x30e/0x550 drivers/infiniband/core/nldev.c:1555 rdma_nl_rcv_msg+0x36d/0x690
    drivers/infiniband/core/netlink.c:195 rdma_nl_rcv_skb drivers/infiniband/core/netlink.c:239 [inline]
    rdma_nl_rcv+0x2ee/0x430 drivers/infiniband/core/netlink.c:259 netlink_unicast_kernel
    net/netlink/af_netlink.c:1312 [inline] netlink_unicast+0x533/0x7d0 net/netlink/af_netlink.c:1338
    netlink_sendmsg+0x856/0xd90 net/netlink/af_netlink.c:1927 sock_sendmsg_nosec net/socket.c:654 [inline]
    sock_sendmsg+0xcf/0x120 net/socket.c:674 ____sys_sendmsg+0x6e8/0x810 net/socket.c:2350
    ___sys_sendmsg+0xf3/0x170 net/socket.c:2404 __sys_sendmsg+0xe5/0x1b0 net/socket.c:2433
    do_syscall_64+0x3a/0xb0 arch/x86/entry/common.c:47 entry_SYSCALL_64_after_hwframe+0 ---truncated---
    (CVE-2021-47078)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
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
