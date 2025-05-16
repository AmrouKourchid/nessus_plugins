#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228380);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41058");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41058");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: cachefiles: fix slab-use-after-free in
    fscache_withdraw_volume() We got the following issue in our fault injection stress test:
    ================================================================== BUG: KASAN: slab-use-after-free in
    fscache_withdraw_volume+0x2e1/0x370 Read of size 4 at addr ffff88810680be08 by task ondemand-04-dae/5798
    CPU: 0 PID: 5798 Comm: ondemand-04-dae Not tainted 6.8.0-dirty #565 Call Trace:
    kasan_check_range+0xf6/0x1b0 fscache_withdraw_volume+0x2e1/0x370 cachefiles_withdraw_volume+0x31/0x50
    cachefiles_withdraw_cache+0x3ad/0x900 cachefiles_put_unbind_pincount+0x1f6/0x250
    cachefiles_daemon_release+0x13b/0x290 __fput+0x204/0xa00 task_work_run+0x139/0x230 Allocated by task 5820:
    __kmalloc+0x1df/0x4b0 fscache_alloc_volume+0x70/0x600 __fscache_acquire_volume+0x1c/0x610
    erofs_fscache_register_volume+0x96/0x1a0 erofs_fscache_register_fs+0x49a/0x690
    erofs_fc_fill_super+0x6c0/0xcc0 vfs_get_super+0xa9/0x140 vfs_get_tree+0x8e/0x300 do_new_mount+0x28c/0x580
    [...] Freed by task 5820: kfree+0xf1/0x2c0 fscache_put_volume.part.0+0x5cb/0x9e0
    erofs_fscache_unregister_fs+0x157/0x1b0 erofs_kill_sb+0xd9/0x1c0 deactivate_locked_super+0xa3/0x100
    vfs_get_super+0x105/0x140 vfs_get_tree+0x8e/0x300 do_new_mount+0x28c/0x580 [...]
    ================================================================== Following is the process that triggers
    the issue: mount failed | daemon exit ------------------------------------------------------------
    deactivate_locked_super cachefiles_daemon_release erofs_kill_sb erofs_fscache_unregister_fs
    fscache_relinquish_volume __fscache_relinquish_volume fscache_put_volume(fscache_volume,
    fscache_volume_put_relinquish) zero = __refcount_dec_and_test(&fscache_volume->ref, &ref);
    cachefiles_put_unbind_pincount cachefiles_daemon_unbind cachefiles_withdraw_cache
    cachefiles_withdraw_volumes list_del_init(&volume->cache_link) fscache_free_volume(fscache_volume)
    cache->ops->free_volume cachefiles_free_volume list_del_init(&cachefiles_volume->cache_link);
    kfree(fscache_volume) cachefiles_withdraw_volume fscache_withdraw_volume fscache_volume->n_accesses //
    fscache_volume UAF !!! The fscache_volume in cache->volumes must not have been freed yet, but its
    reference count may be 0. So use the new fscache_try_get_volume() helper function try to get its reference
    count. If the reference count of fscache_volume is 0, fscache_put_volume() is freeing it, so wait for it
    to be removed from cache->volumes. If its reference count is not 0, call cachefiles_withdraw_volume() with
    reference count protection to avoid the above issue. (CVE-2024-41058)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41058");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
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
