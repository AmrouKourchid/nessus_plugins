#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231322);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-50254");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-50254");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Free dynamically allocated bits
    in bpf_iter_bits_destroy() bpf_iter_bits_destroy() uses kit->nr_bits <= 64 to check whether the bits are
    dynamically allocated. However, the check is incorrect and may cause a kmemleak as shown below:
    unreferenced object 0xffff88812628c8c0 (size 32): comm swapper/0, pid 1, jiffies 4294727320 hex dump
    (first 32 bytes): b0 c1 55 f5 81 88 ff ff f0 f0 f0 f0 f0 f0 f0 f0 ..U........... f0 f0 f0 f0 f0 f0 f0 f0
    00 00 00 00 00 00 00 00 .............. backtrace (crc 781e32cc): [<00000000c452b4ab>]
    kmemleak_alloc+0x4b/0x80 [<0000000004e09f80>] __kmalloc_node_noprof+0x480/0x5c0 [<00000000597124d6>]
    __alloc.isra.0+0x89/0xb0 [<000000004ebfffcd>] alloc_bulk+0x2af/0x720 [<00000000d9c10145>]
    prefill_mem_cache+0x7f/0xb0 [<00000000ff9738ff>] bpf_mem_alloc_init+0x3e2/0x610 [<000000008b616eac>]
    bpf_global_ma_init+0x19/0x30 [<00000000fc473efc>] do_one_initcall+0xd3/0x3c0 [<00000000ec81498c>]
    kernel_init_freeable+0x66a/0x940 [<00000000b119f72f>] kernel_init+0x20/0x160 [<00000000f11ac9a7>]
    ret_from_fork+0x3c/0x70 [<0000000004671da4>] ret_from_fork_asm+0x1a/0x30 That is because nr_bits will be
    set as zero in bpf_iter_bits_next() after all bits have been iterated. Fix the issue by setting kit->bit
    to kit->nr_bits instead of setting kit->nr_bits to zero when the iteration completes in
    bpf_iter_bits_next(). In addition, use !nr_bits || bits >= nr_bits to check whether the iteration is
    complete and still use nr_bits > 64 to indicate whether bits are dynamically allocated. The !nr_bits
    check is necessary because bpf_iter_bits_new() may fail before setting kit->nr_bits, and this condition
    will stop the iteration early instead of accessing the zeroed or freed kit->bits. Considering the initial
    value of kit->bits is -1 and the type of kit->nr_bits is unsigned int, change the type of kit->nr_bits to
    int. The potential overflow problem will be handled in the following patch. (CVE-2024-50254)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/09");
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
