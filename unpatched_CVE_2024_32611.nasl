#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227653);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-32611");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-32611");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - HDF5 Library through 1.14.3 may use an uninitialized value in H5A__attr_release_table in H5Aint.c.
    (CVE-2024-32611)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32611");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/09");
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
     "hdf5-helpers",
     "hdf5-tools",
     "libhdf5-103",
     "libhdf5-103-1",
     "libhdf5-cpp-103",
     "libhdf5-cpp-103-1",
     "libhdf5-dev",
     "libhdf5-doc",
     "libhdf5-fortran-102",
     "libhdf5-hl-100",
     "libhdf5-hl-cpp-100",
     "libhdf5-hl-fortran-100",
     "libhdf5-java",
     "libhdf5-jni",
     "libhdf5-mpi-dev",
     "libhdf5-mpich-103",
     "libhdf5-mpich-103-1",
     "libhdf5-mpich-cpp-103-1",
     "libhdf5-mpich-dev",
     "libhdf5-mpich-fortran-102",
     "libhdf5-mpich-hl-100",
     "libhdf5-mpich-hl-cpp-100",
     "libhdf5-mpich-hl-fortran-100",
     "libhdf5-openmpi-103",
     "libhdf5-openmpi-103-1",
     "libhdf5-openmpi-cpp-103-1",
     "libhdf5-openmpi-dev",
     "libhdf5-openmpi-fortran-102",
     "libhdf5-openmpi-hl-100",
     "libhdf5-openmpi-hl-cpp-100",
     "libhdf5-openmpi-hl-fortran-100"
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
       "match_one": {
        "os_version": [
         "11",
         "12"
        ]
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
