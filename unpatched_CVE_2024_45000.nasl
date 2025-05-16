#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229015);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-45000");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-45000");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: fs/netfs/fscache_cookie: add missing
    n_accesses check This fixes a NULL pointer dereference bug due to a data race which looks like this:
    BUG: kernel NULL pointer dereference, address: 0000000000000008 #PF: supervisor read access in kernel mode
    #PF: error_code(0x0000) - not-present page PGD 0 P4D 0 Oops: 0000 [#1] SMP PTI CPU: 33 PID: 16573 Comm:
    kworker/u97:799 Not tainted 6.8.7-cm4all1-hp+ #43 Hardware name: HP ProLiant DL380 Gen9/ProLiant DL380
    Gen9, BIOS P89 10/17/2018 Workqueue: events_unbound netfs_rreq_write_to_cache_work RIP:
    0010:cachefiles_prepare_write+0x30/0xa0 Code: 57 41 56 45 89 ce 41 55 49 89 cd 41 54 49 89 d4 55 53 48 89
    fb 48 83 ec 08 48 8b 47 08 48 83 7f 10 00 48 89 34 24 48 8b 68 20 <48> 8b 45 08 4c 8b 38 74 45 49 8b 7f 50
    e8 4e a9 b0 ff 48 8b 73 10 RSP: 0018:ffffb4e78113bde0 EFLAGS: 00010286 RAX: ffff976126be6d10 RBX:
    ffff97615cdb8438 RCX: 0000000000020000 RDX: ffff97605e6c4c68 RSI: ffff97605e6c4c60 RDI: ffff97615cdb8438
    RBP: 0000000000000000 R08: 0000000000278333 R09: 0000000000000001 R10: ffff97605e6c4600 R11:
    0000000000000001 R12: ffff97605e6c4c68 R13: 0000000000020000 R14: 0000000000000001 R15: ffff976064fe2c00
    FS: 0000000000000000(0000) GS:ffff9776dfd40000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 CR2: 0000000000000008 CR3: 000000005942c002 CR4: 00000000001706f0 Call Trace: <TASK>
    ? __die+0x1f/0x70 ? page_fault_oops+0x15d/0x440 ? search_module_extables+0xe/0x40 ?
    fixup_exception+0x22/0x2f0 ? exc_page_fault+0x5f/0x100 ? asm_exc_page_fault+0x22/0x30 ?
    cachefiles_prepare_write+0x30/0xa0 netfs_rreq_write_to_cache_work+0x135/0x2e0 process_one_work+0x137/0x2c0
    worker_thread+0x2e9/0x400 ? __pfx_worker_thread+0x10/0x10 kthread+0xcc/0x100 ? __pfx_kthread+0x10/0x10
    ret_from_fork+0x30/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30 </TASK> Modules linked in:
    CR2: 0000000000000008 ---[ end trace 0000000000000000 ]--- This happened because
    fscache_cookie_state_machine() was slow and was still running while another process invoked
    fscache_unuse_cookie(); this led to a fscache_cookie_lru_do_one() call, setting the
    FSCACHE_COOKIE_DO_LRU_DISCARD flag, which was picked up by fscache_cookie_state_machine(), withdrawing the
    cookie via cachefiles_withdraw_cookie(), clearing cookie->cache_priv. At the same time, yet another
    process invoked cachefiles_prepare_write(), which found a NULL pointer in this code line: struct
    cachefiles_object *object = cachefiles_cres_object(cres); The next line crashes, obviously: struct
    cachefiles_cache *cache = object->volume->cache; During cachefiles_prepare_write(), the n_accesses
    counter is non-zero (via fscache_begin_operation()). The cookie must not be withdrawn until it drops to
    zero. The counter is checked by fscache_cookie_state_machine() before switching to
    FSCACHE_COOKIE_STATE_RELINQUISHING and FSCACHE_COOKIE_STATE_WITHDRAWING (in case
    FSCACHE_COOKIE_STATE_FAILED), but not for FSCACHE_COOKIE_STATE_LRU_DISCARDING (case
    FSCACHE_COOKIE_STATE_ACTIVE). This patch adds the missing check. With a non-zero access counter, the
    function returns and the next fscache_end_cookie_access() call will queue another
    fscache_cookie_state_machine() call to handle the still-pending FSCACHE_COOKIE_DO_LRU_DISCARD.
    (CVE-2024-45000)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45000");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
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
