#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227495);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26768");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26768");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: LoongArch: Change
    acpi_core_pic[NR_CPUS] to acpi_core_pic[MAX_CORE_PIC] With default config, the value of NR_CPUS is 64.
    When HW platform has more then 64 cpus, system will crash on these platforms. MAX_CORE_PIC is the maximum
    cpu number in MADT table (max physical number) which can exceed the supported maximum cpu number (NR_CPUS,
    max logical number), but kernel should not crash. Kernel should boot cpus with NR_CPUS, let the remainder
    cpus stay in BIOS. The potential crash reason is that the array acpi_core_pic[NR_CPUS] can be overflowed
    when parsing MADT table, and it is obvious that CORE_PIC should be corresponding to physical core rather
    than logical core, so it is better to define the array as acpi_core_pic[MAX_CORE_PIC]. With the patch,
    system can boot up 64 vcpus with qemu parameter -smp 128, otherwise system will crash with the following
    message. [ 0.000000] CPU 0 Unable to handle kernel paging request at virtual address 0000420000004259, era
    == 90000000037a5f0c, ra == 90000000037a46ec [ 0.000000] Oops[#1]: [ 0.000000] CPU: 0 PID: 0 Comm: swapper
    Not tainted 6.8.0-rc2+ #192 [ 0.000000] Hardware name: QEMU QEMU Virtual Machine, BIOS unknown 2/2/2022 [
    0.000000] pc 90000000037a5f0c ra 90000000037a46ec tp 9000000003c90000 sp 9000000003c93d60 [ 0.000000] a0
    0000000000000019 a1 9000000003d93bc0 a2 0000000000000000 a3 9000000003c93bd8 [ 0.000000] a4
    9000000003c93a74 a5 9000000083c93a67 a6 9000000003c938f0 a7 0000000000000005 [ 0.000000] t0
    0000420000004201 t1 0000000000000000 t2 0000000000000001 t3 0000000000000001 [ 0.000000] t4
    0000000000000003 t5 0000000000000000 t6 0000000000000030 t7 0000000000000063 [ 0.000000] t8
    0000000000000014 u0 ffffffffffffffff s9 0000000000000000 s0 9000000003caee98 [ 0.000000] s1
    90000000041b0480 s2 9000000003c93da0 s3 9000000003c93d98 s4 9000000003c93d90 [ 0.000000] s5
    9000000003caa000 s6 000000000a7fd000 s7 000000000f556b60 s8 000000000e0a4330 [ 0.000000] ra:
    90000000037a46ec platform_init+0x214/0x250 [ 0.000000] ERA: 90000000037a5f0c efi_runtime_init+0x30/0x94 [
    0.000000] CRMD: 000000b0 (PLV0 -IE -DA +PG DACF=CC DACM=CC -WE) [ 0.000000] PRMD: 00000000 (PPLV0 -PIE
    -PWE) [ 0.000000] EUEN: 00000000 (-FPE -SXE -ASXE -BTE) [ 0.000000] ECFG: 00070800 (LIE=11 VS=7) [
    0.000000] ESTAT: 00010000 [PIL] (IS= ECode=1 EsubCode=0) [ 0.000000] BADV: 0000420000004259 [ 0.000000]
    PRID: 0014c010 (Loongson-64bit, Loongson-3A5000) [ 0.000000] Modules linked in: [ 0.000000] Process
    swapper (pid: 0, threadinfo=(____ptrval____), task=(____ptrval____)) [ 0.000000] Stack : 9000000003c93a14
    9000000003800898 90000000041844f8 90000000037a46ec [ 0.000000] 000000000a7fd000 0000000008290000
    0000000000000000 0000000000000000 [ 0.000000] 0000000000000000 0000000000000000 00000000019d8000
    000000000f556b60 [ 0.000000] 000000000a7fd000 000000000f556b08 9000000003ca7700 9000000003800000 [
    0.000000] 9000000003c93e50 9000000003800898 9000000003800108 90000000037a484c [ 0.000000] 000000000e0a4330
    000000000f556b60 000000000a7fd000 000000000f556b08 [ 0.000000] 9000000003ca7700 9000000004184000
    0000000000200000 000000000e02b018 [ 0.000000] 000000000a7fd000 90000000037a0790 9000000003800108
    0000000000000000 [ 0.000000] 0000000000000000 000000000e0a4330 000000000f556b60 000000000a7fd000 [
    0.000000] 000000000f556b08 000000000eaae298 000000000eaa5040 0000000000200000 [ 0.000000] ... [ 0.000000]
    Call Trace: [ 0.000000] [<90000000037a5f0c>] efi_runtime_init+0x30/0x94 [ 0.000000] [<90000000037a46ec>]
    platform_init+0x214/0x250 [ 0.000000] [<90000000037a484c>] setup_arch+0x124/0x45c [ 0.000000]
    [<90000000037a0790>] start_kernel+0x90/0x670 [ 0.000000] [<900000000378b0d8>] kernel_entry+0xd8/0xdc
    (CVE-2024-26768)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26768");

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
