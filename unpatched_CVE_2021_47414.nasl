#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230121);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47414");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47414");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: riscv: Flush current cpu icache before
    other cpus On SiFive Unmatched, I recently fell onto the following BUG when booting: [ 0.000000] ftrace:
    allocating 36610 entries in 144 pages [ 0.000000] Oops - illegal instruction [#1] [ 0.000000] Modules
    linked in: [ 0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 5.13.1+ #5 [ 0.000000] Hardware name:
    SiFive HiFive Unmatched A00 (DT) [ 0.000000] epc : riscv_cpuid_to_hartid_mask+0x6/0xae [ 0.000000] ra :
    __sbi_rfence_v02+0xc8/0x10a [ 0.000000] epc : ffffffff80007240 ra : ffffffff80009964 sp : ffffffff81803e10
    [ 0.000000] gp : ffffffff81a1ea70 tp : ffffffff8180f500 t0 : ffffffe07fe30000 [ 0.000000] t1 :
    0000000000000004 t2 : 0000000000000000 s0 : ffffffff81803e60 [ 0.000000] s1 : 0000000000000000 a0 :
    ffffffff81a22238 a1 : ffffffff81803e10 [ 0.000000] a2 : 0000000000000000 a3 : 0000000000000000 a4 :
    0000000000000000 [ 0.000000] a5 : 0000000000000000 a6 : ffffffff8000989c a7 : 0000000052464e43 [ 0.000000]
    s2 : ffffffff81a220c8 s3 : 0000000000000000 s4 : 0000000000000000 [ 0.000000] s5 : 0000000000000000 s6 :
    0000000200000100 s7 : 0000000000000001 [ 0.000000] s8 : ffffffe07fe04040 s9 : ffffffff81a22c80 s10:
    0000000000001000 [ 0.000000] s11: 0000000000000004 t3 : 0000000000000001 t4 : 0000000000000008 [ 0.000000]
    t5 : ffffffcf04000808 t6 : ffffffe3ffddf188 [ 0.000000] status: 0000000200000100 badaddr: 0000000000000000
    cause: 0000000000000002 [ 0.000000] [<ffffffff80007240>] riscv_cpuid_to_hartid_mask+0x6/0xae [ 0.000000]
    [<ffffffff80009474>] sbi_remote_fence_i+0x1e/0x26 [ 0.000000] [<ffffffff8000b8f4>]
    flush_icache_all+0x12/0x1a [ 0.000000] [<ffffffff8000666c>] patch_text_nosync+0x26/0x32 [ 0.000000]
    [<ffffffff8000884e>] ftrace_init_nop+0x52/0x8c [ 0.000000] [<ffffffff800f051e>]
    ftrace_process_locs.isra.0+0x29c/0x360 [ 0.000000] [<ffffffff80a0e3c6>] ftrace_init+0x80/0x130 [ 0.000000]
    [<ffffffff80a00f8c>] start_kernel+0x5c4/0x8f6 [ 0.000000] ---[ end trace f67eb9af4d8d492b ]--- [ 0.000000]
    Kernel panic - not syncing: Attempted to kill the idle task! [ 0.000000] ---[ end Kernel panic - not
    syncing: Attempted to kill the idle task! ]--- While ftrace is looping over a list of addresses to patch,
    it always failed when patching the same function: riscv_cpuid_to_hartid_mask. Looking at the backtrace,
    the illegal instruction is encountered in this same function. However, patch_text_nosync, after patching
    the instructions, calls flush_icache_range. But looking at what happens in this function:
    flush_icache_range -> flush_icache_all -> sbi_remote_fence_i -> __sbi_rfence_v02 ->
    riscv_cpuid_to_hartid_mask The icache and dcache of the current cpu are never synchronized between the
    patching of riscv_cpuid_to_hartid_mask and calling this same function. So fix this by flushing the current
    cpu's icache before asking for the other cpus to do the same. (CVE-2021-47414)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47414");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

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
    "name": [
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
     "linux-azure-cloud-tools-5.4.0-1010",
     "linux-azure-fips",
     "linux-azure-headers-5.4.0-1010",
     "linux-azure-tools-5.4.0-1010",
     "linux-bluefield",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-buildinfo-5.4.0-1009-aws",
     "linux-buildinfo-5.4.0-1009-gcp",
     "linux-buildinfo-5.4.0-1009-kvm",
     "linux-buildinfo-5.4.0-1009-oracle",
     "linux-buildinfo-5.4.0-1010-azure",
     "linux-buildinfo-5.4.0-26-generic",
     "linux-buildinfo-5.4.0-26-generic-lpae",
     "linux-cloud-tools-5.4.0-1009-aws",
     "linux-cloud-tools-5.4.0-1009-kvm",
     "linux-cloud-tools-5.4.0-1009-oracle",
     "linux-cloud-tools-5.4.0-1010-azure",
     "linux-cloud-tools-5.4.0-26",
     "linux-cloud-tools-5.4.0-26-generic",
     "linux-cloud-tools-5.4.0-26-generic-lpae",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-fips",
     "linux-gcp-fips",
     "linux-gcp-headers-5.4.0-1009",
     "linux-gcp-tools-5.4.0-1009",
     "linux-headers-5.4.0-1008-raspi",
     "linux-headers-5.4.0-1009-aws",
     "linux-headers-5.4.0-1009-gcp",
     "linux-headers-5.4.0-1009-kvm",
     "linux-headers-5.4.0-1009-oracle",
     "linux-headers-5.4.0-1010-azure",
     "linux-headers-5.4.0-26",
     "linux-headers-5.4.0-26-generic",
     "linux-headers-5.4.0-26-generic-lpae",
     "linux-ibm",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-image-5.4.0-1009-aws",
     "linux-image-5.4.0-1009-aws-dbgsym",
     "linux-image-5.4.0-1009-kvm",
     "linux-image-5.4.0-1009-kvm-dbgsym",
     "linux-image-unsigned-5.4.0-1009-gcp",
     "linux-image-unsigned-5.4.0-1009-gcp-dbgsym",
     "linux-image-unsigned-5.4.0-1009-oracle",
     "linux-image-unsigned-5.4.0-1009-oracle-dbgsym",
     "linux-image-unsigned-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic",
     "linux-image-unsigned-5.4.0-26-generic-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic-lpae",
     "linux-image-unsigned-5.4.0-26-generic-lpae-dbgsym",
     "linux-image-unsigned-5.4.0-26-lowlatency",
     "linux-iot",
     "linux-kvm-cloud-tools-5.4.0-1009",
     "linux-kvm-headers-5.4.0-1009",
     "linux-kvm-tools-5.4.0-1009",
     "linux-libc-dev",
     "linux-modules-5.4.0-1008-raspi",
     "linux-modules-5.4.0-1009-aws",
     "linux-modules-5.4.0-1009-gcp",
     "linux-modules-5.4.0-1009-kvm",
     "linux-modules-5.4.0-1009-oracle",
     "linux-modules-5.4.0-1010-azure",
     "linux-modules-5.4.0-26-generic",
     "linux-modules-5.4.0-26-generic-lpae",
     "linux-modules-5.4.0-26-lowlatency",
     "linux-modules-extra-5.4.0-1009-aws",
     "linux-modules-extra-5.4.0-1009-gcp",
     "linux-modules-extra-5.4.0-1009-kvm",
     "linux-modules-extra-5.4.0-1009-oracle",
     "linux-modules-extra-5.4.0-1010-azure",
     "linux-modules-extra-5.4.0-26-generic",
     "linux-modules-extra-5.4.0-26-generic-lpae",
     "linux-modules-extra-5.4.0-26-lowlatency",
     "linux-oracle-headers-5.4.0-1009",
     "linux-oracle-tools-5.4.0-1009",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-source-5.4.0",
     "linux-tools-5.4.0-1008-raspi",
     "linux-tools-5.4.0-1009-aws",
     "linux-tools-5.4.0-1009-gcp",
     "linux-tools-5.4.0-1009-kvm",
     "linux-tools-5.4.0-1009-oracle",
     "linux-tools-5.4.0-1010-azure",
     "linux-tools-5.4.0-26",
     "linux-tools-5.4.0-26-generic",
     "linux-tools-5.4.0-26-generic-lpae",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-kvm",
     "linux-xilinx-zynqmp"
    ],
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
        "os_version": "20.04"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
