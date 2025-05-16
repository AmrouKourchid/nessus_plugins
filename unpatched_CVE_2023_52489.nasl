#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226652);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52489");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52489");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/sparsemem: fix race in accessing
    memory_section->usage The below race is observed on a PFN which falls into the device memory region with
    the system memory configuration where PFN's are such that [ZONE_NORMAL ZONE_DEVICE ZONE_NORMAL]. Since
    normal zone start and end pfn contains the device memory PFN's as well, the compaction triggered will try
    on the device memory PFN's too though they end up in NOP(because pfn_to_online_page() returns NULL for
    ZONE_DEVICE memory sections). When from other core, the section mappings are being removed for the
    ZONE_DEVICE region, that the PFN in question belongs to, on which compaction is currently being operated
    is resulting into the kernel crash with CONFIG_SPASEMEM_VMEMAP enabled. The crash logs can be seen at [1].
    compact_zone() memunmap_pages ------------- --------------- __pageblock_pfn_to_page ...... (a)pfn_valid():
    valid_section()//return true (b)__remove_pages()-> sparse_remove_section()-> section_deactivate(): [Free
    the array ms->usage and set ms->usage = NULL] pfn_section_valid() [Access ms->usage which is NULL] NOTE:
    From the above it can be said that the race is reduced to between the pfn_valid()/pfn_section_valid() and
    the section deactivate with SPASEMEM_VMEMAP enabled. The commit b943f045a9af(mm/sparse: fix kernel crash
    with pfn_section_valid check) tried to address the same problem by clearing the SECTION_HAS_MEM_MAP with
    the expectation of valid_section() returns false thus ms->usage is not accessed. Fix this issue by the
    below steps: a) Clear SECTION_HAS_MEM_MAP before freeing the ->usage. b) RCU protected read side critical
    section will either return NULL when SECTION_HAS_MEM_MAP is cleared or can successfully access ->usage. c)
    Free the ->usage with kfree_rcu() and set ms->usage = NULL. No attempt will be made to access ->usage
    after this as the SECTION_HAS_MEM_MAP is cleared thus valid_section() return false. Thanks to David/Pavan
    for their inputs on this patch. [1] https://lore.kernel.org/linux-
    mm/994410bb-89aa-d987-1f50-f514903c55aa@quicinc.com/ On Snapdragon SoC, with the mentioned memory
    configuration of PFN's as [ZONE_NORMAL ZONE_DEVICE ZONE_NORMAL], we are able to see bunch of issues daily
    while testing on a device farm. For this particular issue below is the log. Though the below log is not
    directly pointing to the pfn_section_valid(){ ms->usage;}, when we loaded this dump on T32 lauterbach
    tool, it is pointing. [ 540.578056] Unable to handle kernel NULL pointer dereference at virtual address
    0000000000000000 [ 540.578068] Mem abort info: [ 540.578070] ESR = 0x0000000096000005 [ 540.578073] EC =
    0x25: DABT (current EL), IL = 32 bits [ 540.578077] SET = 0, FnV = 0 [ 540.578080] EA = 0, S1PTW = 0 [
    540.578082] FSC = 0x05: level 1 translation fault [ 540.578085] Data abort info: [ 540.578086] ISV = 0,
    ISS = 0x00000005 [ 540.578088] CM = 0, WnR = 0 [ 540.579431] pstate: 82400005 (Nzcv daif +PAN -UAO +TCO
    -DIT -SSBSBTYPE=--) [ 540.579436] pc : __pageblock_pfn_to_page+0x6c/0x14c [ 540.579454] lr :
    compact_zone+0x994/0x1058 [ 540.579460] sp : ffffffc03579b510 [ 540.579463] x29: ffffffc03579b510 x28:
    0000000000235800 x27:000000000000000c [ 540.579470] x26: 0000000000235c00 x25: 0000000000000068
    x24:ffffffc03579b640 [ 540.579477] x23: 0000000000000001 x22: ffffffc03579b660 x21:0000000000000000 [
    540.579483] x20: 0000000000235bff x19: ffffffdebf7e3940 x18:ffffffdebf66d140 [ 540.579489] x17:
    00000000739ba063 x16: 00000000739ba063 x15:00000000009f4bff [ 540.579495] x14: 0000008000000000 x13:
    0000000000000000 x12:0000000000000001 [ 540.579501] x11: 0000000000000000 x10: 0000000000000000 x9
    :ffffff897d2cd440 [ 540.579507] x8 : 0000000000000000 x7 : 0000000000000000 x6 :ffffffc03579b5b4 [
    540.579512] x5 : 0000000000027f25 x4 : ffffffc03579b5b8 x3 :0000000000000 ---truncated--- (CVE-2023-52489)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52489");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
  },
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
