#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228821);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41057");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41057");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: cachefiles: fix slab-use-after-free in
    cachefiles_withdraw_cookie() We got the following issue in our fault injection stress test:
    ================================================================== BUG: KASAN: slab-use-after-free in
    cachefiles_withdraw_cookie+0x4d9/0x600 Read of size 8 at addr ffff888118efc000 by task kworker/u78:0/109
    CPU: 13 PID: 109 Comm: kworker/u78:0 Not tainted 6.8.0-dirty #566 Call Trace: <TASK>
    kasan_report+0x93/0xc0 cachefiles_withdraw_cookie+0x4d9/0x600 fscache_cookie_state_machine+0x5c8/0x1230
    fscache_cookie_worker+0x91/0x1c0 process_one_work+0x7fa/0x1800 [...] Allocated by task 117:
    kmalloc_trace+0x1b3/0x3c0 cachefiles_acquire_volume+0xf3/0x9c0 fscache_create_volume_work+0x97/0x150
    process_one_work+0x7fa/0x1800 [...] Freed by task 120301: kfree+0xf1/0x2c0
    cachefiles_withdraw_cache+0x3fa/0x920 cachefiles_put_unbind_pincount+0x1f6/0x250
    cachefiles_daemon_release+0x13b/0x290 __fput+0x204/0xa00 task_work_run+0x139/0x230 do_exit+0x87a/0x29b0
    [...] ================================================================== Following is the process that
    triggers the issue: p1 | p2 ------------------------------------------------------------
    fscache_begin_lookup fscache_begin_volume_access fscache_cache_is_live(fscache_cache)
    cachefiles_daemon_release cachefiles_put_unbind_pincount cachefiles_daemon_unbind
    cachefiles_withdraw_cache fscache_withdraw_cache fscache_set_cache_state(cache,
    FSCACHE_CACHE_IS_WITHDRAWN); cachefiles_withdraw_objects(cache) fscache_wait_for_objects(fscache)
    atomic_read(&fscache_cache->object_count) == 0 fscache_perform_lookup cachefiles_lookup_cookie
    cachefiles_alloc_object refcount_set(&object->ref, 1); object->volume = volume
    fscache_count_object(vcookie->cache); atomic_inc(&fscache_cache->object_count) cachefiles_withdraw_volumes
    cachefiles_withdraw_volume fscache_withdraw_volume __cachefiles_free_volume kfree(cachefiles_volume)
    fscache_cookie_state_machine cachefiles_withdraw_cookie cache = object->volume->cache; //
    cachefiles_volume UAF !!! After setting FSCACHE_CACHE_IS_WITHDRAWN, wait for all the cookie lookups to
    complete first, and then wait for fscache_cache->object_count == 0 to avoid the cookie exiting after the
    volume has been freed and triggering the above issue. Therefore call fscache_withdraw_volume() before
    calling cachefiles_withdraw_objects(). This way, after setting FSCACHE_CACHE_IS_WITHDRAWN, only the
    following two cases will occur: 1) fscache_begin_lookup fails in fscache_begin_volume_access(). 2)
    fscache_withdraw_volume() will ensure that fscache_count_object() has been executed before calling
    fscache_wait_for_objects(). (CVE-2024-41057)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41057");

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
