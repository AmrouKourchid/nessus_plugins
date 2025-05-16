#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228079);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26841");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26841");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: LoongArch: Update cpu_sibling_map when
    disabling nonboot CPUs Update cpu_sibling_map when disabling nonboot CPUs by defining & calling
    clear_cpu_sibling_map(), otherwise we get such errors on SMT systems: jump label: negative count! WARNING:
    CPU: 6 PID: 45 at kernel/jump_label.c:263 __static_key_slow_dec_cpuslocked+0xec/0x100 CPU: 6 PID: 45 Comm:
    cpuhp/6 Not tainted 6.8.0-rc5+ #1340 pc 90000000004c302c ra 90000000004c302c tp 90000001005bc000 sp
    90000001005bfd20 a0 000000000000001b a1 900000000224c278 a2 90000001005bfb58 a3 900000000224c280 a4
    900000000224c278 a5 90000001005bfb50 a6 0000000000000001 a7 0000000000000001 t0 ce87a4763eb5234a t1
    ce87a4763eb5234a t2 0000000000000000 t3 0000000000000000 t4 0000000000000006 t5 0000000000000000 t6
    0000000000000064 t7 0000000000001964 t8 000000000009ebf6 u0 9000000001f2a068 s9 0000000000000000 s0
    900000000246a2d8 s1 ffffffffffffffff s2 ffffffffffffffff s3 90000000021518c0 s4 0000000000000040 s5
    9000000002151058 s6 9000000009828e40 s7 00000000000000b4 s8 0000000000000006 ra: 90000000004c302c
    __static_key_slow_dec_cpuslocked+0xec/0x100 ERA: 90000000004c302c
    __static_key_slow_dec_cpuslocked+0xec/0x100 CRMD: 000000b0 (PLV0 -IE -DA +PG DACF=CC DACM=CC -WE) PRMD:
    00000004 (PPLV0 +PIE -PWE) EUEN: 00000000 (-FPE -SXE -ASXE -BTE) ECFG: 00071c1c (LIE=2-4,10-12 VS=7)
    ESTAT: 000c0000 [BRK] (IS= ECode=12 EsubCode=0) PRID: 0014d000 (Loongson-64bit, Loongson-3A6000-HV) CPU: 6
    PID: 45 Comm: cpuhp/6 Not tainted 6.8.0-rc5+ #1340 Stack : 0000000000000000 900000000203f258
    900000000179afc8 90000001005bc000 90000001005bf980 0000000000000000 90000001005bf988 9000000001fe0be0
    900000000224c280 900000000224c278 90000001005bf8c0 0000000000000001 0000000000000001 ce87a4763eb5234a
    0000000007f38000 90000001003f8cc0 0000000000000000 0000000000000006 0000000000000000 4c206e6f73676e6f
    6f4c203a656d616e 000000000009ec99 0000000007f38000 0000000000000000 900000000214b000 9000000001fe0be0
    0000000000000004 0000000000000000 0000000000000107 0000000000000009 ffffffffffafdabe 00000000000000b4
    0000000000000006 90000000004c302c 9000000000224528 00005555939a0c7c 00000000000000b0 0000000000000004
    0000000000000000 0000000000071c1c ... Call Trace: [<9000000000224528>] show_stack+0x48/0x1a0
    [<900000000179afc8>] dump_stack_lvl+0x78/0xa0 [<9000000000263ed0>] __warn+0x90/0x1a0 [<90000000017419b8>]
    report_bug+0x1b8/0x280 [<900000000179c564>] do_bp+0x264/0x420 [<90000000004c302c>]
    __static_key_slow_dec_cpuslocked+0xec/0x100 [<90000000002b4d7c>] sched_cpu_deactivate+0x2fc/0x300
    [<9000000000266498>] cpuhp_invoke_callback+0x178/0x8a0 [<9000000000267f70>] cpuhp_thread_fun+0xf0/0x240
    [<90000000002a117c>] smpboot_thread_fn+0x1dc/0x2e0 [<900000000029a720>] kthread+0x140/0x160
    [<9000000000222288>] ret_from_kernel_thread+0xc/0xa4 (CVE-2024-26841)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26841");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/Ubuntu", "Host/Ubuntu/release");

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
     "btrfs-modules-6.1.0-29-alpha-generic-di",
     "cdrom-core-modules-6.1.0-29-alpha-generic-di",
     "ext4-modules-6.1.0-29-alpha-generic-di",
     "fat-modules-6.1.0-29-alpha-generic-di",
     "isofs-modules-6.1.0-29-alpha-generic-di",
     "jfs-modules-6.1.0-29-alpha-generic-di",
     "kernel-image-6.1.0-29-alpha-generic-di",
     "linux-doc",
     "linux-doc-6.1",
     "linux-headers-6.1.0-29-common",
     "linux-headers-6.1.0-29-common-rt",
     "linux-source",
     "linux-source-6.1",
     "linux-support-6.1.0-29",
     "loop-modules-6.1.0-29-alpha-generic-di",
     "nic-modules-6.1.0-29-alpha-generic-di",
     "nic-shared-modules-6.1.0-29-alpha-generic-di",
     "nic-wireless-modules-6.1.0-29-alpha-generic-di",
     "pata-modules-6.1.0-29-alpha-generic-di",
     "ppp-modules-6.1.0-29-alpha-generic-di",
     "scsi-core-modules-6.1.0-29-alpha-generic-di",
     "scsi-modules-6.1.0-29-alpha-generic-di",
     "scsi-nic-modules-6.1.0-29-alpha-generic-di",
     "serial-modules-6.1.0-29-alpha-generic-di",
     "usb-serial-modules-6.1.0-29-alpha-generic-di",
     "xfs-modules-6.1.0-29-alpha-generic-di"
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
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "12"
       }
      }
     ]
    }
   ]
  },
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
