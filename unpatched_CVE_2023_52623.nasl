#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227241);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52623");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52623");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: SUNRPC: Fix a suspicious RCU usage
    warning I received the following warning while running cthon against an ontap server running pNFS: [
    57.202521] ============================= [ 57.202522] WARNING: suspicious RCU usage [ 57.202523]
    6.7.0-rc3-g2cc14f52aeb7 #41492 Not tainted [ 57.202525] ----------------------------- [ 57.202525]
    net/sunrpc/xprtmultipath.c:349 RCU-list traversed in non-reader section!! [ 57.202527] other info that
    might help us debug this: [ 57.202528] rcu_scheduler_active = 2, debug_locks = 1 [ 57.202529] no locks
    held by test5/3567. [ 57.202530] stack backtrace: [ 57.202532] CPU: 0 PID: 3567 Comm: test5 Not tainted
    6.7.0-rc3-g2cc14f52aeb7 #41492 5b09971b4965c0aceba19f3eea324a4a806e227e [ 57.202534] Hardware name: QEMU
    Standard PC (Q35 + ICH9, 2009), BIOS unknown 2/2/2022 [ 57.202536] Call Trace: [ 57.202537] <TASK> [
    57.202540] dump_stack_lvl+0x77/0xb0 [ 57.202551] lockdep_rcu_suspicious+0x154/0x1a0 [ 57.202556]
    rpc_xprt_switch_has_addr+0x17c/0x190 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6] [ 57.202596]
    rpc_clnt_setup_test_and_add_xprt+0x50/0x180 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6] [ 57.202621]
    ? rpc_clnt_add_xprt+0x254/0x300 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6] [ 57.202646]
    rpc_clnt_add_xprt+0x27a/0x300 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6] [ 57.202671] ?
    __pfx_rpc_clnt_setup_test_and_add_xprt+0x10/0x10 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6] [
    57.202696] nfs4_pnfs_ds_connect+0x345/0x760 [nfsv4 c716d88496ded0ea6d289bbea684fa996f9b57a9] [ 57.202728]
    ? __pfx_nfs4_test_session_trunk+0x10/0x10 [nfsv4 c716d88496ded0ea6d289bbea684fa996f9b57a9] [ 57.202754]
    nfs4_fl_prepare_ds+0x75/0xc0 [nfs_layout_nfsv41_files e3a4187f18ae8a27b630f9feae6831b584a9360a] [
    57.202760] filelayout_write_pagelist+0x4a/0x200 [nfs_layout_nfsv41_files
    e3a4187f18ae8a27b630f9feae6831b584a9360a] [ 57.202765] pnfs_generic_pg_writepages+0xbe/0x230 [nfsv4
    c716d88496ded0ea6d289bbea684fa996f9b57a9] [ 57.202788] __nfs_pageio_add_request+0x3fd/0x520 [nfs
    6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202813] nfs_pageio_add_request+0x18b/0x390 [nfs
    6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202831] nfs_do_writepage+0x116/0x1e0 [nfs
    6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202849] nfs_writepages_callback+0x13/0x30 [nfs
    6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202866] write_cache_pages+0x265/0x450 [ 57.202870] ?
    __pfx_nfs_writepages_callback+0x10/0x10 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202891]
    nfs_writepages+0x141/0x230 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202913]
    do_writepages+0xd2/0x230 [ 57.202917] ? filemap_fdatawrite_wbc+0x5c/0x80 [ 57.202921]
    filemap_fdatawrite_wbc+0x67/0x80 [ 57.202924] filemap_write_and_wait_range+0xd9/0x170 [ 57.202930]
    nfs_wb_all+0x49/0x180 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902] [ 57.202947]
    nfs4_file_flush+0x72/0xb0 [nfsv4 c716d88496ded0ea6d289bbea684fa996f9b57a9] [ 57.202969]
    __se_sys_close+0x46/0xd0 [ 57.202972] do_syscall_64+0x68/0x100 [ 57.202975] ? do_syscall_64+0x77/0x100 [
    57.202976] ? do_syscall_64+0x77/0x100 [ 57.202979] entry_SYSCALL_64_after_hwframe+0x6e/0x76 [ 57.202982]
    RIP: 0033:0x7fe2b12e4a94 [ 57.202985] Code: 00 f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f 84 00 00 00 00 00
    90 f3 0f 1e fa 80 3d d5 18 0e 00 00 74 13 b8 03 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 44 c3 0f 1f 00 48 83
    ec 18 89 7c 24 0c e8 c3 [ 57.202987] RSP: 002b:00007ffe857ddb38 EFLAGS: 00000202 ORIG_RAX:
    0000000000000003 [ 57.202989] RAX: ffffffffffffffda RBX: 00007ffe857dfd68 RCX: 00007fe2b12e4a94 [
    57.202991] RDX: 0000000000002000 RSI: 00007ffe857ddc40 RDI: 0000000000000003 [ 57.202992] RBP:
    00007ffe857dfc50 R08: 7fffffffffffffff R09: 0000000065650f49 [ 57.202993] R10: 00007f ---truncated---
    (CVE-2023-52623)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52623");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
