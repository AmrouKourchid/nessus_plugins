#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226624);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52797");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52797");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drivers: perf: Check find_first_bit()
    return value We must check the return value of find_first_bit() before using the return value as an index
    array since it happens to overflow the array and then panic: [ 107.318430] Kernel BUG [#1] [ 107.319434]
    CPU: 3 PID: 1238 Comm: kill Tainted: G E 6.6.0-rc6ubuntu-defconfig #2 [ 107.319465] Hardware name: riscv-
    virtio,qemu (DT) [ 107.319551] epc : pmu_sbi_ovf_handler+0x3a4/0x3ae [ 107.319840] ra :
    pmu_sbi_ovf_handler+0x52/0x3ae [ 107.319868] epc : ffffffff80a0a77c ra : ffffffff80a0a42a sp :
    ffffaf83fecda350 [ 107.319884] gp : ffffffff823961a8 tp : ffffaf8083db1dc0 t0 : ffffaf83fecda480 [
    107.319899] t1 : ffffffff80cafe62 t2 : 000000000000ff00 s0 : ffffaf83fecda520 [ 107.319921] s1 :
    ffffaf83fecda380 a0 : 00000018fca29df0 a1 : ffffffffffffffff [ 107.319936] a2 : 0000000001073734 a3 :
    0000000000000004 a4 : 0000000000000000 [ 107.319951] a5 : 0000000000000040 a6 : 000000001d1c8774 a7 :
    0000000000504d55 [ 107.319965] s2 : ffffffff82451f10 s3 : ffffffff82724e70 s4 : 000000000000003f [
    107.319980] s5 : 0000000000000011 s6 : ffffaf8083db27c0 s7 : 0000000000000000 [ 107.319995] s8 :
    0000000000000001 s9 : 00007fffb45d6558 s10: 00007fffb45d81a0 [ 107.320009] s11: ffffaf7ffff60000 t3 :
    0000000000000004 t4 : 0000000000000000 [ 107.320023] t5 : ffffaf7f80000000 t6 : ffffaf8000000000 [
    107.320037] status: 0000000200000100 badaddr: 0000000000000000 cause: 0000000000000003 [ 107.320081]
    [<ffffffff80a0a77c>] pmu_sbi_ovf_handler+0x3a4/0x3ae [ 107.320112] [<ffffffff800b42d0>]
    handle_percpu_devid_irq+0x9e/0x1a0 [ 107.320131] [<ffffffff800ad92c>] generic_handle_domain_irq+0x28/0x36
    [ 107.320148] [<ffffffff8065f9f8>] riscv_intc_irq+0x36/0x4e [ 107.320166] [<ffffffff80caf4a0>]
    handle_riscv_irq+0x54/0x86 [ 107.320189] [<ffffffff80cb0036>] do_irq+0x64/0x96 [ 107.320271] Code: 85a6
    855e b097 ff7f 80e7 9220 b709 9002 4501 bbd9 (9002) 6097 [ 107.320585] ---[ end trace 0000000000000000
    ]--- [ 107.320704] Kernel panic - not syncing: Fatal exception in interrupt [ 107.320775] SMP: stopping
    secondary CPUs [ 107.321219] Kernel Offset: 0x0 from 0xffffffff80000000 [ 107.333051] ---[ end Kernel
    panic - not syncing: Fatal exception in interrupt ]--- (CVE-2023-52797)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52797");

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
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
