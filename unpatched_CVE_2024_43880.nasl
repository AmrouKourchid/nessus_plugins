#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229541);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-43880");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-43880");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_erp: Fix object
    nesting warning ACLs in Spectrum-2 and newer ASICs can reside in the algorithmic TCAM (A-TCAM) or in the
    ordinary circuit TCAM (C-TCAM). The former can contain more ACLs (i.e., tc filters), but the number of
    masks in each region (i.e., tc chain) is limited. In order to mitigate the effects of the above
    limitation, the device allows filters to share a single mask if their masks only differ in up to 8
    consecutive bits. For example, dst_ip/25 can be represented using dst_ip/24 with a delta of 1 bit. The
    C-TCAM does not have a limit on the number of masks being used (and therefore does not support mask
    aggregation), but can contain a limited number of filters. The driver uses the objagg library to perform
    the mask aggregation by passing it objects that consist of the filter's mask and whether the filter is to
    be inserted into the A-TCAM or the C-TCAM since filters in different TCAMs cannot share a mask. The set of
    created objects is dependent on the insertion order of the filters and is not necessarily optimal.
    Therefore, the driver will periodically ask the library to compute a more optimal set (hints) by looking
    at all the existing objects. When the library asks the driver whether two objects can be aggregated the
    driver only compares the provided masks and ignores the A-TCAM / C-TCAM indication. This is the right
    thing to do since the goal is to move as many filters as possible to the A-TCAM. The driver also forbids
    two identical masks from being aggregated since this can only happen if one was intentionally put in the
    C-TCAM to avoid a conflict in the A-TCAM. The above can result in the following set of hints: H1: {mask X,
    A-TCAM} -> H2: {mask Y, A-TCAM} // X is Y + delta H3: {mask Y, C-TCAM} -> H4: {mask Z, A-TCAM} // Y is Z +
    delta After getting the hints from the library the driver will start migrating filters from one region to
    another while consulting the computed hints and instructing the device to perform a lookup in both regions
    during the transition. Assuming a filter with mask X is being migrated into the A-TCAM in the new region,
    the hints lookup will return H1. Since H2 is the parent of H1, the library will try to find the object
    associated with it and create it if necessary in which case another hints lookup (recursive) will be
    performed. This hints lookup for {mask Y, A-TCAM} will either return H2 or H3 since the driver passes the
    library an object comparison function that ignores the A-TCAM / C-TCAM indication. This can eventually
    lead to nested objects which are not supported by the library [1]. Fix by removing the object comparison
    function from both the driver and the library as the driver was the only user. That way the lookup will
    only return exact matches. I do not have a reliable reproducer that can reproduce the issue in a timely
    manner, but before the fix the issue would reproduce in several minutes and with the fix it does not
    reproduce in over an hour. Note that the current usefulness of the hints is limited because they include
    the C-TCAM indication and represent aggregation that cannot actually happen. This will be addressed in
    net-next. [1] WARNING: CPU: 0 PID: 153 at lib/objagg.c:170 objagg_obj_parent_assign+0xb5/0xd0 Modules
    linked in: CPU: 0 PID: 153 Comm: kworker/0:18 Not tainted 6.9.0-rc6-custom-g70fbc2c1c38b #42 Hardware
    name: Mellanox Technologies Ltd. MSN3700C/VMOD0008, BIOS 5.11 10/10/2018 Workqueue: mlxsw_core
    mlxsw_sp_acl_tcam_vregion_rehash_work RIP: 0010:objagg_obj_parent_assign+0xb5/0xd0 [...] Call Trace:
    <TASK> __objagg_obj_get+0x2bb/0x580 objagg_obj_get+0xe/0x80 mlxsw_sp_acl_erp_mask_get+0xb5/0xf0
    mlxsw_sp_acl_atcam_entry_add+0xe8/0x3c0 mlxsw_sp_acl_tcam_entry_create+0x5e/0xa0
    mlxsw_sp_acl_tcam_vchunk_migrate_one+0x16b/0x270 mlxsw_sp_acl_tcam_vregion_rehash_work+0xbe/0x510
    process_one_work+0x151/0x370 (CVE-2024-43880)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43880");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/21");
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
  },
  {
   "product": {
    "name": [
     "kernel",
     "kernel-rt"
    ],
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
