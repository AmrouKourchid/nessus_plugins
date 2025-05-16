#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229052);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36926");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36926");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: powerpc/pseries/iommu: LPAR panics
    during boot up with a frozen PE At the time of LPAR boot up, partition firmware provides Open Firmware
    property ibm,dma-window for the PE. This property is provided on the PCI bus the PE is attached to. There
    are execptions where the partition firmware might not provide this property for the PE at the time of LPAR
    boot up. One of the scenario is where the firmware has frozen the PE due to some error condition. This PE
    is frozen for 24 hours or unless the whole system is reinitialized. Within this time frame, if the LPAR is
    booted, the frozen PE will be presented to the LPAR but ibm,dma-window property could be missing. Today,
    under these circumstances, the LPAR oopses with NULL pointer dereference, when configuring the PCI bus the
    PE is attached to. BUG: Kernel NULL pointer dereference on read at 0x000000c8 Faulting instruction
    address: 0xc0000000001024c0 Oops: Kernel access of bad area, sig: 7 [#1] LE PAGE_SIZE=64K MMU=Radix SMP
    NR_CPUS=2048 NUMA pSeries Modules linked in: Supported: Yes CPU: 0 PID: 1 Comm: swapper/0 Not tainted
    6.4.0-150600.9-default #1 Hardware name: IBM,9043-MRX POWER10 (raw) 0x800200 0xf000006 of:IBM,FW1060.00
    (NM1060_023) hv:phyp pSeries NIP: c0000000001024c0 LR: c0000000001024b0 CTR: c000000000102450 REGS:
    c0000000037db5c0 TRAP: 0300 Not tainted (6.4.0-150600.9-default) MSR: 8000000002009033
    <SF,VEC,EE,ME,IR,DR,RI,LE> CR: 28000822 XER: 00000000 CFAR: c00000000010254c DAR: 00000000000000c8 DSISR:
    00080000 IRQMASK: 0 ... NIP [c0000000001024c0] pci_dma_bus_setup_pSeriesLP+0x70/0x2a0 LR
    [c0000000001024b0] pci_dma_bus_setup_pSeriesLP+0x60/0x2a0 Call Trace:
    pci_dma_bus_setup_pSeriesLP+0x60/0x2a0 (unreliable) pcibios_setup_bus_self+0x1c0/0x370
    __of_scan_bus+0x2f8/0x330 pcibios_scan_phb+0x280/0x3d0 pcibios_init+0x88/0x12c do_one_initcall+0x60/0x320
    kernel_init_freeable+0x344/0x3e4 kernel_init+0x34/0x1d0 ret_from_kernel_user_thread+0x14/0x1c
    (CVE-2024-36926)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36926");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
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
