#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226235);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52506");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52506");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: LoongArch: Set all reserved memblocks
    on Node#0 at initialization After commit 61167ad5fecdea (mm: pass nid to reserve_bootmem_region()) we
    get a panic if DEFERRED_STRUCT_PAGE_INIT is enabled: [ 0.000000] CPU 0 Unable to handle kernel paging
    request at virtual address 0000000000002b82, era == 90000000040e3f28, ra == 90000000040e3f18 [ 0.000000]
    Oops[#1]: [ 0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.5.0+ #733 [ 0.000000] pc 90000000040e3f28
    ra 90000000040e3f18 tp 90000000046f4000 sp 90000000046f7c90 [ 0.000000] a0 0000000000000001 a1
    0000000000200000 a2 0000000000000040 a3 90000000046f7ca0 [ 0.000000] a4 90000000046f7ca4 a5
    0000000000000000 a6 90000000046f7c38 a7 0000000000000000 [ 0.000000] t0 0000000000000002 t1
    9000000004b00ac8 t2 90000000040e3f18 t3 90000000040f0800 [ 0.000000] t4 00000000000f0000 t5
    80000000ffffe07e t6 0000000000000003 t7 900000047fff5e20 [ 0.000000] t8 aaaaaaaaaaaaaaab u0
    0000000000000018 s9 0000000000000000 s0 fffffefffe000000 [ 0.000000] s1 0000000000000000 s2
    0000000000000080 s3 0000000000000040 s4 0000000000000000 [ 0.000000] s5 0000000000000000 s6
    fffffefffe000000 s7 900000000470b740 s8 9000000004ad4000 [ 0.000000] ra: 90000000040e3f18
    reserve_bootmem_region+0xec/0x21c [ 0.000000] ERA: 90000000040e3f28 reserve_bootmem_region+0xfc/0x21c [
    0.000000] CRMD: 000000b0 (PLV0 -IE -DA +PG DACF=CC DACM=CC -WE) [ 0.000000] PRMD: 00000000 (PPLV0 -PIE
    -PWE) [ 0.000000] EUEN: 00000000 (-FPE -SXE -ASXE -BTE) [ 0.000000] ECFG: 00070800 (LIE=11 VS=7) [
    0.000000] ESTAT: 00010800 [PIL] (IS=11 ECode=1 EsubCode=0) [ 0.000000] BADV: 0000000000002b82 [ 0.000000]
    PRID: 0014d000 (Loongson-64bit, Loongson-3A6000) [ 0.000000] Modules linked in: [ 0.000000] Process
    swapper (pid: 0, threadinfo=(____ptrval____), task=(____ptrval____)) [ 0.000000] Stack : 0000000000000000
    9000000002eb5430 0000003a00000020 90000000045ccd00 [ 0.000000] 900000000470e000 90000000002c1918
    0000000000000000 9000000004110780 [ 0.000000] 00000000fe6c0000 0000000480000000 9000000004b4e368
    9000000004110748 [ 0.000000] 0000000000000000 900000000421ca84 9000000004620000 9000000004564970 [
    0.000000] 90000000046f7d78 9000000002cc9f70 90000000002c1918 900000000470e000 [ 0.000000] 9000000004564970
    90000000040bc0e0 90000000046f7d78 0000000000000000 [ 0.000000] 0000000000004000 90000000045ccd00
    0000000000000000 90000000002c1918 [ 0.000000] 90000000002c1900 900000000470b700 9000000004b4df78
    9000000004620000 [ 0.000000] 90000000046200a8 90000000046200a8 0000000000000000 9000000004218b2c [
    0.000000] 9000000004270008 0000000000000001 0000000000000000 90000000045ccd00 [ 0.000000] ... [ 0.000000]
    Call Trace: [ 0.000000] [<90000000040e3f28>] reserve_bootmem_region+0xfc/0x21c [ 0.000000]
    [<900000000421ca84>] memblock_free_all+0x114/0x350 [ 0.000000] [<9000000004218b2c>]
    mm_core_init+0x138/0x3cc [ 0.000000] [<9000000004200e38>] start_kernel+0x488/0x7a4 [ 0.000000]
    [<90000000040df0d8>] kernel_entry+0xd8/0xdc [ 0.000000] [ 0.000000] Code: 02eb21ad 00410f4c 380c31ac
    <262b818d> 6800b70d 02c1c196 0015001c 57fe4bb1 260002cd The reason is early memblock_reserve() in
    memblock_init() set node id to MAX_NUMNODES, making NODE_DATA(nid) a NULL dereference in the call chain
    reserve_bootmem_region() -> init_reserved_page(). After memblock_init(), those late calls of
    memblock_reserve() operate on subregions of memblock .memory regions. As a result, these reserved regions
    will be set to the correct node at the first iteration of memmap_init_reserved_pages(). So set all
    reserved memblocks on Node#0 at initialization can avoid this panic. (CVE-2023-52506)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52506");

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
     "linux-aws-fips",
     "linux-azure-fips",
     "linux-fips",
     "linux-gcp-fips",
     "linux-intel-iot-realtime",
     "linux-realtime"
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
        "os_version": "22.04"
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
