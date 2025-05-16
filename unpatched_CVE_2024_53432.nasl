#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231508);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-53432");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-53432");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - While parsing certain malformed PLY files, PCL version 1.14.1 crashes due to an uncaught std::out_of_range
    exception in PCLPointCloud2::at. This issue could potentially be exploited to cause a denial-of-service
    (DoS) attack when processing untrusted PLY files. (CVE-2024-53432)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53432");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
     "libpcl-apps1.13",
     "libpcl-common1.13",
     "libpcl-dev",
     "libpcl-doc",
     "libpcl-features1.13",
     "libpcl-filters1.13",
     "libpcl-io1.13",
     "libpcl-kdtree1.13",
     "libpcl-keypoints1.13",
     "libpcl-ml1.13",
     "libpcl-octree1.13",
     "libpcl-outofcore1.13",
     "libpcl-people1.13",
     "libpcl-recognition1.13",
     "libpcl-registration1.13",
     "libpcl-sample-consensus1.13",
     "libpcl-search1.13",
     "libpcl-segmentation1.13",
     "libpcl-stereo1.13",
     "libpcl-surface1.13",
     "libpcl-tracking1.13",
     "libpcl-visualization1.13",
     "pcl-tools"
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
     "libpcl-apps1.11",
     "libpcl-common1.11",
     "libpcl-dev",
     "libpcl-doc",
     "libpcl-features1.11",
     "libpcl-filters1.11",
     "libpcl-io1.11",
     "libpcl-kdtree1.11",
     "libpcl-keypoints1.11",
     "libpcl-ml1.11",
     "libpcl-octree1.11",
     "libpcl-outofcore1.11",
     "libpcl-people1.11",
     "libpcl-recognition1.11",
     "libpcl-registration1.11",
     "libpcl-sample-consensus1.11",
     "libpcl-search1.11",
     "libpcl-segmentation1.11",
     "libpcl-stereo1.11",
     "libpcl-surface1.11",
     "libpcl-tracking1.11",
     "libpcl-visualization1.11",
     "pcl-tools"
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
        "os_version": "11"
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
