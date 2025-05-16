#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226629);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52803");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52803");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: SUNRPC: Fix RPC client cleaned up the
    freed pipefs dentries RPC client pipefs dentries cleanup is in separated rpc_remove_pipedir()
    workqueue,which takes care about pipefs superblock locking. In some special scenarios, when kernel frees
    the pipefs sb of the current client and immediately alloctes a new pipefs sb, rpc_remove_pipedir function
    would misjudge the existence of pipefs sb which is not the one it used to hold. As a result, the
    rpc_remove_pipedir would clean the released freed pipefs dentries. To fix this issue, rpc_remove_pipedir
    should check whether the current pipefs sb is consistent with the original pipefs sb. This error can be
    catched by KASAN: ========================================================= [ 250.497700] BUG: KASAN:
    slab-use-after-free in dget_parent+0x195/0x200 [ 250.498315] Read of size 4 at addr ffff88800a2ab804 by
    task kworker/0:18/106503 [ 250.500549] Workqueue: events rpc_free_client_work [ 250.501001] Call Trace: [
    250.502880] kasan_report+0xb6/0xf0 [ 250.503209] ? dget_parent+0x195/0x200 [ 250.503561]
    dget_parent+0x195/0x200 [ 250.503897] ? __pfx_rpc_clntdir_depopulate+0x10/0x10 [ 250.504384]
    rpc_rmdir_depopulate+0x1b/0x90 [ 250.504781] rpc_remove_client_dir+0xf5/0x150 [ 250.505195]
    rpc_free_client_work+0xe4/0x230 [ 250.505598] process_one_work+0x8ee/0x13b0 ... [ 22.039056] Allocated by
    task 244: [ 22.039390] kasan_save_stack+0x22/0x50 [ 22.039758] kasan_set_track+0x25/0x30 [ 22.040109]
    __kasan_slab_alloc+0x59/0x70 [ 22.040487] kmem_cache_alloc_lru+0xf0/0x240 [ 22.040889]
    __d_alloc+0x31/0x8e0 [ 22.041207] d_alloc+0x44/0x1f0 [ 22.041514]
    __rpc_lookup_create_exclusive+0x11c/0x140 [ 22.041987] rpc_mkdir_populate.constprop.0+0x5f/0x110 [
    22.042459] rpc_create_client_dir+0x34/0x150 [ 22.042874] rpc_setup_pipedir_sb+0x102/0x1c0 [ 22.043284]
    rpc_client_register+0x136/0x4e0 [ 22.043689] rpc_new_client+0x911/0x1020 [ 22.044057]
    rpc_create_xprt+0xcb/0x370 [ 22.044417] rpc_create+0x36b/0x6c0 ... [ 22.049524] Freed by task 0: [
    22.049803] kasan_save_stack+0x22/0x50 [ 22.050165] kasan_set_track+0x25/0x30 [ 22.050520]
    kasan_save_free_info+0x2b/0x50 [ 22.050921] __kasan_slab_free+0x10e/0x1a0 [ 22.051306]
    kmem_cache_free+0xa5/0x390 [ 22.051667] rcu_core+0x62c/0x1930 [ 22.051995] __do_softirq+0x165/0x52a [
    22.052347] [ 22.052503] Last potentially related work creation: [ 22.052952] kasan_save_stack+0x22/0x50 [
    22.053313] __kasan_record_aux_stack+0x8e/0xa0 [ 22.053739] __call_rcu_common.constprop.0+0x6b/0x8b0 [
    22.054209] dentry_free+0xb2/0x140 [ 22.054540] __dentry_kill+0x3be/0x540 [ 22.054900]
    shrink_dentry_list+0x199/0x510 [ 22.055293] shrink_dcache_parent+0x190/0x240 [ 22.055703]
    do_one_tree+0x11/0x40 [ 22.056028] shrink_dcache_for_umount+0x61/0x140 [ 22.056461]
    generic_shutdown_super+0x70/0x590 [ 22.056879] kill_anon_super+0x3a/0x60 [ 22.057234]
    rpc_kill_sb+0x121/0x200 (CVE-2023-52803)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52803");

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
