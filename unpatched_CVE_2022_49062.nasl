#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225708);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49062");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49062");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: cachefiles: Fix KASAN slab-out-of-
    bounds in cachefiles_set_volume_xattr Use the actual length of volume coherency data when setting the
    xattr to avoid the following KASAN report. BUG: KASAN: slab-out-of-bounds in
    cachefiles_set_volume_xattr+0xa0/0x350 [cachefiles] Write of size 4 at addr ffff888101e02af4 by task
    kworker/6:0/1347 CPU: 6 PID: 1347 Comm: kworker/6:0 Kdump: loaded Not tainted 5.18.0-rc1-nfs-fscache-
    netfs+ #13 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.14.0-4.fc34 04/01/2014 Workqueue:
    events fscache_create_volume_work [fscache] Call Trace: <TASK> dump_stack_lvl+0x45/0x5a
    print_report.cold+0x5e/0x5db ? __lock_text_start+0x8/0x8 ? cachefiles_set_volume_xattr+0xa0/0x350
    [cachefiles] kasan_report+0xab/0x120 ? cachefiles_set_volume_xattr+0xa0/0x350 [cachefiles]
    kasan_check_range+0xf5/0x1d0 memcpy+0x39/0x60 cachefiles_set_volume_xattr+0xa0/0x350 [cachefiles]
    cachefiles_acquire_volume+0x2be/0x500 [cachefiles] ? __cachefiles_free_volume+0x90/0x90 [cachefiles]
    fscache_create_volume_work+0x68/0x160 [fscache] process_one_work+0x3b7/0x6a0 worker_thread+0x2c4/0x650 ?
    process_one_work+0x6a0/0x6a0 kthread+0x16c/0x1a0 ? kthread_complete_and_exit+0x20/0x20
    ret_from_fork+0x22/0x30 </TASK> Allocated by task 1347: kasan_save_stack+0x1e/0x40
    __kasan_kmalloc+0x81/0xa0 cachefiles_set_volume_xattr+0x76/0x350 [cachefiles]
    cachefiles_acquire_volume+0x2be/0x500 [cachefiles] fscache_create_volume_work+0x68/0x160 [fscache]
    process_one_work+0x3b7/0x6a0 worker_thread+0x2c4/0x650 kthread+0x16c/0x1a0 ret_from_fork+0x22/0x30 The
    buggy address belongs to the object at ffff888101e02af0 which belongs to the cache kmalloc-8 of size 8 The
    buggy address is located 4 bytes inside of 8-byte region [ffff888101e02af0, ffff888101e02af8) The buggy
    address belongs to the physical page: page:00000000a2292d70 refcount:1 mapcount:0 mapping:0000000000000000
    index:0x0 pfn:0x101e02 flags: 0x17ffffc0000200(slab|node=0|zone=2|lastcpupid=0x1fffff) raw:
    0017ffffc0000200 0000000000000000 dead000000000001 ffff888100042280 raw: 0000000000000000 0000000080660066
    00000001ffffffff 0000000000000000 page dumped because: kasan: bad access detected Memory state around the
    buggy address: ffff888101e02980: fc 00 fc fc fc fc 00 fc fc fc fc 00 fc fc fc fc ffff888101e02a00: 00 fc
    fc fc fc 00 fc fc fc fc 00 fc fc fc fc 00 >ffff888101e02a80: fc fc fc fc 00 fc fc fc fc 00 fc fc fc fc 04
    fc ^ ffff888101e02b00: fc fc fc 00 fc fc fc fc 00 fc fc fc fc 00 fc fc ffff888101e02b80: fc fc 00 fc fc fc
    fc 00 fc fc fc fc 00 fc fc fc ==================================================================
    (CVE-2022-49062)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49062");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/26");
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
