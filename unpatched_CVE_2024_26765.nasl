#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228277);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26765");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26765");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: LoongArch: Disable IRQ before
    init_fn() for nonboot CPUs Disable IRQ before init_fn() for nonboot CPUs when hotplug, in order to silence
    such warnings (and also avoid potential errors due to unexpected interrupts): WARNING: CPU: 1 PID: 0 at
    kernel/rcu/tree.c:4503 rcu_cpu_starting+0x214/0x280 CPU: 1 PID: 0 Comm: swapper/1 Not tainted 6.6.17+
    #1198 pc 90000000048e3334 ra 90000000047bd56c tp 900000010039c000 sp 900000010039fdd0 a0 0000000000000001
    a1 0000000000000006 a2 900000000802c040 a3 0000000000000000 a4 0000000000000001 a5 0000000000000004 a6
    0000000000000000 a7 90000000048e3f4c t0 0000000000000001 t1 9000000005c70968 t2 0000000004000000 t3
    000000000005e56e t4 00000000000002e4 t5 0000000000001000 t6 ffffffff80000000 t7 0000000000040000 t8
    9000000007931638 u0 0000000000000006 s9 0000000000000004 s0 0000000000000001 s1 9000000006356ac0 s2
    9000000007244000 s3 0000000000000001 s4 0000000000000001 s5 900000000636f000 s6 7fffffffffffffff s7
    9000000002123940 s8 9000000001ca55f8 ra: 90000000047bd56c tlb_init+0x24c/0x528 ERA: 90000000048e3334
    rcu_cpu_starting+0x214/0x280 CRMD: 000000b0 (PLV0 -IE -DA +PG DACF=CC DACM=CC -WE) PRMD: 00000000 (PPLV0
    -PIE -PWE) EUEN: 00000000 (-FPE -SXE -ASXE -BTE) ECFG: 00071000 (LIE=12 VS=7) ESTAT: 000c0000 [BRK] (IS=
    ECode=12 EsubCode=0) PRID: 0014c010 (Loongson-64bit, Loongson-3A5000) CPU: 1 PID: 0 Comm: swapper/1 Not
    tainted 6.6.17+ #1198 Stack : 0000000000000000 9000000006375000 9000000005b61878 900000010039c000
    900000010039fa30 0000000000000000 900000010039fa38 900000000619a140 9000000006456888 9000000006456880
    900000010039f950 0000000000000001 0000000000000001 cb0cb028ec7e52e1 0000000002b90000 9000000100348700
    0000000000000000 0000000000000001 ffffffff916d12f1 0000000000000003 0000000000040000 9000000007930370
    0000000002b90000 0000000000000004 9000000006366000 900000000619a140 0000000000000000 0000000000000004
    0000000000000000 0000000000000009 ffffffffffc681f2 9000000002123940 9000000001ca55f8 9000000006366000
    90000000047a4828 00007ffff057ded8 00000000000000b0 0000000000000000 0000000000000000 0000000000071000 ...
    Call Trace: [<90000000047a4828>] show_stack+0x48/0x1a0 [<9000000005b61874>] dump_stack_lvl+0x84/0xcc
    [<90000000047f60ac>] __warn+0x8c/0x1e0 [<9000000005b0ab34>] report_bug+0x1b4/0x280 [<9000000005b63110>]
    do_bp+0x2d0/0x480 [<90000000047a2e20>] handle_bp+0x120/0x1c0 [<90000000048e3334>]
    rcu_cpu_starting+0x214/0x280 [<90000000047bd568>] tlb_init+0x248/0x528 [<90000000047a4c44>]
    per_cpu_trap_init+0x124/0x160 [<90000000047a19f4>] cpu_probe+0x494/0xa00 [<90000000047b551c>]
    start_secondary+0x3c/0xc0 [<9000000005b66134>] smpboot_entry+0x50/0x58 (CVE-2024-26765)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26765");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
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
