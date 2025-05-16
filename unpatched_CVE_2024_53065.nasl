#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230356);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-53065");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-53065");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/slab: fix warning caused by
    duplicate kmem_cache creation in kmem_buckets_create Commit b035f5a6d852 (mm: slab: reduce the kmalloc()
    minimum alignment if DMA bouncing possible) reduced ARCH_KMALLOC_MINALIGN to 8 on arm64. However, with
    KASAN_HW_TAGS enabled, arch_slab_minalign() becomes 16. This causes kmalloc_caches[*][8] to be aliased to
    kmalloc_caches[*][16], resulting in kmem_buckets_create() attempting to create a kmem_cache for size 16
    twice. This duplication triggers warnings on boot: [ 2.325108] ------------[ cut here ]------------ [
    2.325135] kmem_cache of name 'memdup_user-16' already exists [ 2.325783] WARNING: CPU: 0 PID: 1 at
    mm/slab_common.c:107 __kmem_cache_create_args+0xb8/0x3b0 [ 2.327957] Modules linked in: [ 2.328550] CPU: 0
    UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.12.0-rc5mm-unstable-arm64+ #12 [ 2.328683] Hardware name: QEMU
    QEMU Virtual Machine, BIOS 2024.02-2 03/11/2024 [ 2.328790] pstate: 61000009 (nZCv daif -PAN -UAO -TCO
    +DIT -SSBS BTYPE=--) [ 2.328911] pc : __kmem_cache_create_args+0xb8/0x3b0 [ 2.328930] lr :
    __kmem_cache_create_args+0xb8/0x3b0 [ 2.328942] sp : ffff800083d6fc50 [ 2.328961] x29: ffff800083d6fc50
    x28: f2ff0000c1674410 x27: ffff8000820b0598 [ 2.329061] x26: 000000007fffffff x25: 0000000000000010 x24:
    0000000000002000 [ 2.329101] x23: ffff800083d6fce8 x22: ffff8000832222e8 x21: ffff800083222388 [ 2.329118]
    x20: f2ff0000c1674410 x19: f5ff0000c16364c0 x18: ffff800083d80030 [ 2.329135] x17: 0000000000000000 x16:
    0000000000000000 x15: 0000000000000000 [ 2.329152] x14: 0000000000000000 x13: 0a73747369786520 x12:
    79646165726c6120 [ 2.329169] x11: 656820747563205b x10: 2d2d2d2d2d2d2d2d x9 : 0000000000000000 [ 2.329194]
    x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000 [ 2.329210] x5 : 0000000000000000 x4 :
    0000000000000000 x3 : 0000000000000000 [ 2.329226] x2 : 0000000000000000 x1 : 0000000000000000 x0 :
    0000000000000000 [ 2.329291] Call trace: [ 2.329407] __kmem_cache_create_args+0xb8/0x3b0 [ 2.329499]
    kmem_buckets_create+0xfc/0x320 [ 2.329526] init_user_buckets+0x34/0x78 [ 2.329540]
    do_one_initcall+0x64/0x3c8 [ 2.329550] kernel_init_freeable+0x26c/0x578 [ 2.329562] kernel_init+0x3c/0x258
    [ 2.329574] ret_from_fork+0x10/0x20 [ 2.329698] ---[ end trace 0000000000000000 ]--- [ 2.403704]
    ------------[ cut here ]------------ [ 2.404716] kmem_cache of name 'msg_msg-16' already exists [
    2.404801] WARNING: CPU: 2 PID: 1 at mm/slab_common.c:107 __kmem_cache_create_args+0xb8/0x3b0 [ 2.404842]
    Modules linked in: [ 2.404971] CPU: 2 UID: 0 PID: 1 Comm: swapper/0 Tainted: G W 6.12.0-rc5mm-unstable-
    arm64+ #12 [ 2.405026] Tainted: [W]=WARN [ 2.405043] Hardware name: QEMU QEMU Virtual Machine, BIOS
    2024.02-2 03/11/2024 [ 2.405057] pstate: 60400009 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) [
    2.405079] pc : __kmem_cache_create_args+0xb8/0x3b0 [ 2.405100] lr : __kmem_cache_create_args+0xb8/0x3b0 [
    2.405111] sp : ffff800083d6fc50 [ 2.405115] x29: ffff800083d6fc50 x28: fbff0000c1674410 x27:
    ffff8000820b0598 [ 2.405135] x26: 000000000000ffd0 x25: 0000000000000010 x24: 0000000000006000 [ 2.405153]
    x23: ffff800083d6fce8 x22: ffff8000832222e8 x21: ffff800083222388 [ 2.405169] x20: fbff0000c1674410 x19:
    fdff0000c163d6c0 x18: ffff800083d80030 [ 2.405185] x17: 0000000000000000 x16: 0000000000000000 x15:
    0000000000000000 [ 2.405201] x14: 0000000000000000 x13: 0a73747369786520 x12: 79646165726c6120 [ 2.405217]
    x11: 656820747563205b x10: 2d2d2d2d2d2d2d2d x9 : 0000000000000000 [ 2.405233] x8 : 0000000000000000 x7 :
    0000000000000000 x6 : 0000000000000000 [ 2.405248] x5 : 0000000000000000 x4 : 0000000000000000 x3 :
    0000000000000000 [ 2.405271] x2 : 0000000000000000 x1 : 0000000000000000 x0 : 0000000000000000 [ 2.405287]
    Call trace: [ 2 ---truncated--- (CVE-2024-53065)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53065");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-lowlatency-hwe-6.11",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "24.04"
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
