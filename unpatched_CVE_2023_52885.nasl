#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227239);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52885");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52885");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: SUNRPC: Fix UAF in
    svc_tcp_listen_data_ready() After the listener svc_sock is freed, and before invoking svc_tcp_accept() for
    the established child sock, there is a window that the newsock retaining a freed listener svc_sock in
    sk_user_data which cloning from parent. In the race window, if data is received on the newsock, we will
    observe use-after-free report in svc_tcp_listen_data_ready(). Reproduce by two tasks: 1. while :; do
    rpc.nfsd 0 ; rpc.nfsd; done 2. while :; do echo  | ncat -4 127.0.0.1 2049 ; done KASAN report:
    ================================================================== BUG: KASAN: slab-use-after-free in
    svc_tcp_listen_data_ready+0x1cf/0x1f0 [sunrpc] Read of size 8 at addr ffff888139d96228 by task nc/102553
    CPU: 7 PID: 102553 Comm: nc Not tainted 6.3.0+ #18 Hardware name: VMware, Inc. VMware Virtual
    Platform/440BX Desktop Reference Platform, BIOS 6.00 11/12/2020 Call Trace: <IRQ> dump_stack_lvl+0x33/0x50
    print_address_description.constprop.0+0x27/0x310 print_report+0x3e/0x70 kasan_report+0xae/0xe0
    svc_tcp_listen_data_ready+0x1cf/0x1f0 [sunrpc] tcp_data_queue+0x9f4/0x20e0
    tcp_rcv_established+0x666/0x1f60 tcp_v4_do_rcv+0x51c/0x850 tcp_v4_rcv+0x23fc/0x2e80
    ip_protocol_deliver_rcu+0x62/0x300 ip_local_deliver_finish+0x267/0x350 ip_local_deliver+0x18b/0x2d0
    ip_rcv+0x2fb/0x370 __netif_receive_skb_one_core+0x166/0x1b0 process_backlog+0x24c/0x5e0
    __napi_poll+0xa2/0x500 net_rx_action+0x854/0xc90 __do_softirq+0x1bb/0x5de do_softirq+0xcb/0x100 </IRQ>
    <TASK> ... </TASK> Allocated by task 102371: kasan_save_stack+0x1e/0x40 kasan_set_track+0x21/0x30
    __kasan_kmalloc+0x7b/0x90 svc_setup_socket+0x52/0x4f0 [sunrpc] svc_addsock+0x20d/0x400 [sunrpc]
    __write_ports_addfd+0x209/0x390 [nfsd] write_ports+0x239/0x2c0 [nfsd] nfsctl_transaction_write+0xac/0x110
    [nfsd] vfs_write+0x1c3/0xae0 ksys_write+0xed/0x1c0 do_syscall_64+0x38/0x90
    entry_SYSCALL_64_after_hwframe+0x72/0xdc Freed by task 102551: kasan_save_stack+0x1e/0x40
    kasan_set_track+0x21/0x30 kasan_save_free_info+0x2a/0x50 __kasan_slab_free+0x106/0x190
    __kmem_cache_free+0x133/0x270 svc_xprt_free+0x1e2/0x350 [sunrpc] svc_xprt_destroy_all+0x25a/0x440 [sunrpc]
    nfsd_put+0x125/0x240 [nfsd] nfsd_svc+0x2cb/0x3c0 [nfsd] write_threads+0x1ac/0x2a0 [nfsd]
    nfsctl_transaction_write+0xac/0x110 [nfsd] vfs_write+0x1c3/0xae0 ksys_write+0xed/0x1c0
    do_syscall_64+0x38/0x90 entry_SYSCALL_64_after_hwframe+0x72/0xdc Fix the UAF by simply doing nothing in
    svc_tcp_listen_data_ready() if state != TCP_LISTEN, that will avoid dereferencing svsk for all child
    socket. (CVE-2023-52885)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52885");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/03");
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
