#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226510);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52562");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52562");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/slab_common: fix slab_caches list
    corruption after kmem_cache_destroy() After the commit in Fixes:, if a module that created a slab cache
    does not release all of its allocated objects before destroying the cache (at rmmod time), we might end up
    releasing the kmem_cache object without removing it from the slab_caches list thus corrupting the list as
    kmem_cache_destroy() ignores the return value from shutdown_cache(), which in turn never removes the
    kmem_cache object from slabs_list in case __kmem_cache_shutdown() fails to release all of the cache's
    slabs. This is easily observable on a kernel built with CONFIG_DEBUG_LIST=y as after that ill release the
    system will immediately trip on list_add, or list_del, assertions similar to the one shown below as soon
    as another kmem_cache gets created, or destroyed: [ 1041.213632] list_del corruption. next->prev should be
    ffff89f596fb5768, but was 52f1e5016aeee75d. (next=ffff89f595a1b268) [ 1041.219165] ------------[ cut here
    ]------------ [ 1041.221517] kernel BUG at lib/list_debug.c:62! [ 1041.223452] invalid opcode: 0000 [#1]
    PREEMPT SMP PTI [ 1041.225408] CPU: 2 PID: 1852 Comm: rmmod Kdump: loaded Tainted: G B W OE 6.5.0 #15 [
    1041.228244] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS edk2-20230524-3.fc37 05/24/2023 [
    1041.231212] RIP: 0010:__list_del_entry_valid+0xae/0xb0 Another quick way to trigger this issue, in a
    kernel with CONFIG_SLUB=y, is to set slub_debug to poison the released objects and then just run cat
    /proc/slabinfo after removing the module that leaks slab objects, in which case the kernel will panic: [
    50.954843] general protection fault, probably for non-canonical address 0xa56b6b6b6b6b6b8b: 0000 [#1]
    PREEMPT SMP PTI [ 50.961545] CPU: 2 PID: 1495 Comm: cat Kdump: loaded Tainted: G B W OE 6.5.0 #15 [
    50.966808] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS edk2-20230524-3.fc37 05/24/2023 [
    50.972663] RIP: 0010:get_slabinfo+0x42/0xf0 This patch fixes this issue by properly checking
    shutdown_cache()'s return value before taking the kmem_cache_release() branch. (CVE-2023-52562)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52562");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/12");
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
