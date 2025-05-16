#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229748);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47536");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47536");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/smc: fix wrong list_del in
    smc_lgr_cleanup_early smc_lgr_cleanup_early() meant to delete the link group from the link group list, but
    it deleted the list head by mistake. This may cause memory corruption since we didn't remove the real link
    group from the list and later memseted the link group structure. We got a list corruption panic when
    testing: [ 231.277259] list_del corruption. prev->next should be ffff8881398a8000, but was
    0000000000000000 [ 231.278222] ------------[ cut here ]------------ [ 231.278726] kernel BUG at
    lib/list_debug.c:53! [ 231.279326] invalid opcode: 0000 [#1] SMP NOPTI [ 231.279803] CPU: 0 PID: 5 Comm:
    kworker/0:0 Not tainted 5.10.46+ #435 [ 231.280466] Hardware name: Alibaba Cloud ECS, BIOS 8c24b4c
    04/01/2014 [ 231.281248] Workqueue: events smc_link_down_work [ 231.281732] RIP:
    0010:__list_del_entry_valid+0x70/0x90 [ 231.282258] Code: 4c 60 82 e8 7d cc 6a 00 0f 0b 48 89 fe 48 c7 c7
    88 4c 60 82 e8 6c cc 6a 00 0f 0b 48 89 fe 48 c7 c7 c0 4c 60 82 e8 5b cc 6a 00 <0f> 0b 48 89 fe 48 c7 c7 00
    4d 60 82 e8 4a cc 6a 00 0f 0b cc cc cc [ 231.284146] RSP: 0018:ffffc90000033d58 EFLAGS: 00010292 [
    231.284685] RAX: 0000000000000054 RBX: ffff8881398a8000 RCX: 0000000000000000 [ 231.285415] RDX:
    0000000000000001 RSI: ffff88813bc18040 RDI: ffff88813bc18040 [ 231.286141] RBP: ffffffff8305ad40 R08:
    0000000000000003 R09: 0000000000000001 [ 231.286873] R10: ffffffff82803da0 R11: ffffc90000033b90 R12:
    0000000000000001 [ 231.287606] R13: 0000000000000000 R14: ffff8881398a8000 R15: 0000000000000003 [
    231.288337] FS: 0000000000000000(0000) GS:ffff88813bc00000(0000) knlGS:0000000000000000 [ 231.289160] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 231.289754] CR2: 0000000000e72058 CR3: 000000010fa96006
    CR4: 00000000003706f0 [ 231.290485] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [
    231.291211] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [ 231.291940] Call Trace: [
    231.292211] smc_lgr_terminate_sched+0x53/0xa0 [ 231.292677] smc_switch_conns+0x75/0x6b0 [ 231.293085] ?
    update_load_avg+0x1a6/0x590 [ 231.293517] ? ttwu_do_wakeup+0x17/0x150 [ 231.293907] ?
    update_load_avg+0x1a6/0x590 [ 231.294317] ? newidle_balance+0xca/0x3d0 [ 231.294716]
    smcr_link_down+0x50/0x1a0 [ 231.295090] ? __wake_up_common_lock+0x77/0x90 [ 231.295534]
    smc_link_down_work+0x46/0x60 [ 231.295933] process_one_work+0x18b/0x350 (CVE-2021-47536)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47536");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/24");
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
