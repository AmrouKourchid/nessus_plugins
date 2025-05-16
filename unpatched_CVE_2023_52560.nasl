#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227176);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52560");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52560");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/damon/vaddr-test: fix memory leak
    in damon_do_test_apply_three_regions() When CONFIG_DAMON_VADDR_KUNIT_TEST=y and making
    CONFIG_DEBUG_KMEMLEAK=y and CONFIG_DEBUG_KMEMLEAK_AUTO_SCAN=y, the below memory leak is detected. Since
    commit 9f86d624292c (mm/damon/vaddr-test: remove unnecessary variables), the damon_destroy_ctx() is
    removed, but still call damon_new_target() and damon_new_region(), the damon_region which is allocated by
    kmem_cache_alloc() in damon_new_region() and the damon_target which is allocated by kmalloc in
    damon_new_target() are not freed. And the damon_region which is allocated in damon_new_region() in
    damon_set_regions() is also not freed. So use damon_destroy_target to free all the damon_regions and
    damon_target. unreferenced object 0xffff888107c9a940 (size 64): comm kunit_try_catch, pid 1069, jiffies
    4294670592 (age 732.761s) hex dump (first 32 bytes): 00 00 00 00 00 00 00 00 06 00 00 00 6b 6b 6b 6b
    ............kkkk 60 c7 9c 07 81 88 ff ff f8 cb 9c 07 81 88 ff ff `............... backtrace:
    [<ffffffff817e0167>] kmalloc_trace+0x27/0xa0 [<ffffffff819c11cf>] damon_new_target+0x3f/0x1b0
    [<ffffffff819c7d55>] damon_do_test_apply_three_regions.constprop.0+0x95/0x3e0 [<ffffffff819c82be>]
    damon_test_apply_three_regions1+0x21e/0x260 [<ffffffff829fce6a>]
    kunit_generic_run_threadfn_adapter+0x4a/0x90 [<ffffffff81237cf6>] kthread+0x2b6/0x380 [<ffffffff81097add>]
    ret_from_fork+0x2d/0x70 [<ffffffff81003791>] ret_from_fork_asm+0x11/0x20 unreferenced object
    0xffff8881079cc740 (size 56): comm kunit_try_catch, pid 1069, jiffies 4294670592 (age 732.761s) hex dump
    (first 32 bytes): 05 00 00 00 00 00 00 00 14 00 00 00 00 00 00 00 ................ 6b 6b 6b 6b 6b 6b 6b 6b
    00 00 00 00 6b 6b 6b 6b kkkkkkkk....kkkk backtrace: [<ffffffff819bc492>] damon_new_region+0x22/0x1c0
    [<ffffffff819c7d91>] damon_do_test_apply_three_regions.constprop.0+0xd1/0x3e0 [<ffffffff819c82be>]
    damon_test_apply_three_regions1+0x21e/0x260 [<ffffffff829fce6a>]
    kunit_generic_run_threadfn_adapter+0x4a/0x90 [<ffffffff81237cf6>] kthread+0x2b6/0x380 [<ffffffff81097add>]
    ret_from_fork+0x2d/0x70 [<ffffffff81003791>] ret_from_fork_asm+0x11/0x20 unreferenced object
    0xffff888107c9ac40 (size 64): comm kunit_try_catch, pid 1071, jiffies 4294670595 (age 732.843s) hex dump
    (first 32 bytes): 00 00 00 00 00 00 00 00 06 00 00 00 6b 6b 6b 6b ............kkkk a0 cc 9c 07 81 88 ff ff
    78 a1 76 07 81 88 ff ff ........x.v..... backtrace: [<ffffffff817e0167>] kmalloc_trace+0x27/0xa0
    [<ffffffff819c11cf>] damon_new_target+0x3f/0x1b0 [<ffffffff819c7d55>]
    damon_do_test_apply_three_regions.constprop.0+0x95/0x3e0 [<ffffffff819c851e>]
    damon_test_apply_three_regions2+0x21e/0x260 [<ffffffff829fce6a>]
    kunit_generic_run_threadfn_adapter+0x4a/0x90 [<ffffffff81237cf6>] kthread+0x2b6/0x380 [<ffffffff81097add>]
    ret_from_fork+0x2d/0x70 [<ffffffff81003791>] ret_from_fork_asm+0x11/0x20 unreferenced object
    0xffff8881079ccc80 (size 56): comm kunit_try_catch, pid 1071, jiffies 4294670595 (age 732.843s) hex dump
    (first 32 bytes): 05 00 00 00 00 00 00 00 14 00 00 00 00 00 00 00 ................ 6b 6b 6b 6b 6b 6b 6b 6b
    00 00 00 00 6b 6b 6b 6b kkkkkkkk....kkkk backtrace: [<ffffffff819bc492>] damon_new_region+0x22/0x1c0
    [<ffffffff819c7d91>] damon_do_test_apply_three_regions.constprop.0+0xd1/0x3e0 [<ffffffff819c851e>]
    damon_test_apply_three_regions2+0x21e/0x260 [<ffffffff829fce6a>]
    kunit_generic_run_threadfn_adapter+0x4a/0x90 [<ffffffff81237cf6>] kthread+0x2b6/0x380 [<ffffffff81097add>]
    ret_from_fork+0x2d/0x70 [<ffff ---truncated--- (CVE-2023-52560)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52560");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/02");
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
