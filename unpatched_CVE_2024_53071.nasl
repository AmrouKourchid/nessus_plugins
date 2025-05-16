#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231991);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-53071");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-53071");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/panthor: Be stricter about IO
    mapping flags The current panthor_device_mmap_io() implementation has two issues: 1. For mapping
    DRM_PANTHOR_USER_FLUSH_ID_MMIO_OFFSET, panthor_device_mmap_io() bails if VM_WRITE is set, but does not
    clear VM_MAYWRITE. That means userspace can use mprotect() to make the mapping writable later on. This is
    a classic Linux driver gotcha. I don't think this actually has any impact in practice: When the GPU is
    powered, writes to the FLUSH_ID seem to be ignored; and when the GPU is not powered, the
    dummy_latest_flush page provided by the driver is deliberately designed to not do any flushes, so the only
    thing writing to the dummy_latest_flush could achieve would be to make *more* flushes happen. 2.
    panthor_device_mmap_io() does not block MAP_PRIVATE mappings (which are mappings without the VM_SHARED
    flag). MAP_PRIVATE in combination with VM_MAYWRITE indicates that the VMA has copy-on-write semantics,
    which for VM_PFNMAP are semi-supported but fairly cursed. In particular, in such a mapping, the driver can
    only install PTEs during mmap() by calling remap_pfn_range() (because remap_pfn_range() wants to **store
    the physical address of the mapped physical memory into the vm_pgoff of the VMA**); installing PTEs later
    on with a fault handler (as panthor does) is not supported in private mappings, and so if you try to fault
    in such a mapping, vmf_insert_pfn_prot() splats when it hits a BUG() check. Fix it by clearing the
    VM_MAYWRITE flag (userspace writing to the FLUSH_ID doesn't make sense) and requiring VM_SHARED (copy-on-
    write semantics for the FLUSH_ID don't make sense). Reproducers for both scenarios are in the notes of my
    patch on the mailing list; I tested that these bugs exist on a Rock 5B machine. Note that I only compile-
    tested the patch, I haven't tested it; I don't have a working kernel build setup for the test machine yet.
    Please test it before applying it. (CVE-2024-53071)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53071");

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
