#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228960);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-46740");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-46740");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: binder: fix UAF caused by offsets
    overwrite Binder objects are processed and copied individually into the target buffer during transactions.
    Any raw data in-between these objects is copied as well. However, this raw data copy lacks an out-of-
    bounds check. If the raw data exceeds the data section size then the copy overwrites the offsets section.
    This eventually triggers an error that attempts to unwind the processed objects. However, at this point
    the offsets used to index these objects are now corrupted. Unwinding with corrupted offsets can result in
    decrements of arbitrary nodes and lead to their premature release. Other users of such nodes are left with
    a dangling pointer triggering a use-after-free. This issue is made evident by the following KASAN report
    (trimmed): ================================================================== BUG: KASAN: slab-use-after-
    free in _raw_spin_lock+0xe4/0x19c Write of size 4 at addr ffff47fc91598f04 by task binder-util/743 CPU: 9
    UID: 0 PID: 743 Comm: binder-util Not tainted 6.11.0-rc4 #1 Hardware name: linux,dummy-virt (DT) Call
    trace: _raw_spin_lock+0xe4/0x19c binder_free_buf+0x128/0x434 binder_thread_write+0x8a4/0x3260
    binder_ioctl+0x18f0/0x258c [...] Allocated by task 743: __kmalloc_cache_noprof+0x110/0x270
    binder_new_node+0x50/0x700 binder_transaction+0x413c/0x6da8 binder_thread_write+0x978/0x3260
    binder_ioctl+0x18f0/0x258c [...] Freed by task 745: kfree+0xbc/0x208 binder_thread_read+0x1c5c/0x37d4
    binder_ioctl+0x16d8/0x258c [...] ================================================================== To
    avoid this issue, let's check that the raw data copy is within the boundaries of the data section.
    (CVE-2024-46740)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46740");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/18");
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
    "name": "linux-azure-fde",
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
  },
  {
   "product": {
    "name": "linux-azure-fde-5.15",
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
