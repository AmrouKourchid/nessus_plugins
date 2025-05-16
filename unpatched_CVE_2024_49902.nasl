#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231180);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-49902");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-49902");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: jfs: check if leafidx greater than num
    leaves per dmap tree syzbot report a out of bounds in dbSplit, it because dmt_leafidx greater than num
    leaves per dmap tree, add a checking for dmt_leafidx in dbFindLeaf. Shaggy: Modified sanity check to apply
    to control pages as well as leaf pages. (CVE-2024-49902)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49902");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
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
    "name": [
     "linux-aws-5.4",
     "linux-aws-cloud-tools-4.15.0-1007",
     "linux-aws-headers-4.15.0-1007",
     "linux-aws-tools-4.15.0-1007",
     "linux-azure-4.15",
     "linux-cloud-tools-4.15.0-1007-aws",
     "linux-cloud-tools-4.15.0-1008-kvm",
     "linux-cloud-tools-4.15.0-20",
     "linux-cloud-tools-4.15.0-20-generic",
     "linux-cloud-tools-4.15.0-20-generic-lpae",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-gcp-4.15",
     "linux-headers-4.15.0-1007-aws",
     "linux-headers-4.15.0-1008-kvm",
     "linux-headers-4.15.0-20",
     "linux-headers-4.15.0-20-generic",
     "linux-headers-4.15.0-20-generic-lpae",
     "linux-headers-4.15.0-20-lowlatency",
     "linux-image-4.15.0-1007-aws",
     "linux-image-4.15.0-1007-aws-dbgsym",
     "linux-image-4.15.0-1008-kvm",
     "linux-image-4.15.0-1008-kvm-dbgsym",
     "linux-image-unsigned-4.15.0-20-generic",
     "linux-image-unsigned-4.15.0-20-generic-dbgsym",
     "linux-image-unsigned-4.15.0-20-generic-lpae",
     "linux-image-unsigned-4.15.0-20-generic-lpae-dbgsym",
     "linux-image-unsigned-4.15.0-20-lowlatency",
     "linux-kvm-cloud-tools-4.15.0-1008",
     "linux-kvm-headers-4.15.0-1008",
     "linux-kvm-tools-4.15.0-1008",
     "linux-libc-dev",
     "linux-modules-4.15.0-1007-aws",
     "linux-modules-4.15.0-1008-kvm",
     "linux-modules-4.15.0-20-generic",
     "linux-modules-4.15.0-20-generic-lpae",
     "linux-modules-4.15.0-20-lowlatency",
     "linux-modules-extra-4.15.0-1007-aws",
     "linux-modules-extra-4.15.0-1008-kvm",
     "linux-modules-extra-4.15.0-20-generic",
     "linux-modules-extra-4.15.0-20-generic-lpae",
     "linux-modules-extra-4.15.0-20-lowlatency",
     "linux-oracle",
     "linux-oracle-5.4",
     "linux-raspi-5.4",
     "linux-source-4.15.0",
     "linux-tools-4.15.0-1007-aws",
     "linux-tools-4.15.0-1008-kvm",
     "linux-tools-4.15.0-20",
     "linux-tools-4.15.0-20-generic",
     "linux-tools-4.15.0-20-generic-lpae",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-kvm"
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
        "os_version": "18.04"
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
     "linux-azure-fde-5.15",
     "linux-azure-fips",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-fips",
     "linux-gcp-fips",
     "linux-headers-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-iot",
     "linux-modules-5.4.0-1008-raspi",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-tools-5.4.0-1008-raspi"
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
    "name": [
     "linux-aws-hwe",
     "linux-azure",
     "linux-gcp",
     "linux-hwe",
     "linux-kvm",
     "linux-oracle"
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
        "os_version": "16.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-azure-cloud-tools-6.8.0-1007",
     "linux-azure-headers-6.8.0-1007",
     "linux-azure-tools-6.8.0-1007",
     "linux-buildinfo-6.8.0-1005-ibm",
     "linux-buildinfo-6.8.0-1005-oem",
     "linux-buildinfo-6.8.0-1007-azure",
     "linux-cloud-tools-6.8.0-1005-ibm",
     "linux-cloud-tools-6.8.0-1005-oem",
     "linux-cloud-tools-6.8.0-1007-azure",
     "linux-headers-6.8.0-1005-ibm",
     "linux-headers-6.8.0-1005-oem",
     "linux-headers-6.8.0-1007-azure",
     "linux-ibm-cloud-tools-6.8.0-1005",
     "linux-ibm-cloud-tools-common",
     "linux-ibm-headers-6.8.0-1005",
     "linux-ibm-source-6.8.0",
     "linux-ibm-tools-6.8.0-1005",
     "linux-ibm-tools-common",
     "linux-image-unsigned-6.8.0-1005-ibm",
     "linux-image-unsigned-6.8.0-1005-ibm-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oem",
     "linux-image-unsigned-6.8.0-1005-oem-dbgsym",
     "linux-image-unsigned-6.8.0-1007-azure",
     "linux-image-unsigned-6.8.0-1007-azure-dbgsym",
     "linux-lowlatency-hwe-6.11",
     "linux-modules-6.8.0-1005-ibm",
     "linux-modules-6.8.0-1005-oem",
     "linux-modules-6.8.0-1007-azure",
     "linux-modules-extra-6.8.0-1005-ibm",
     "linux-modules-extra-6.8.0-1005-oem",
     "linux-modules-extra-6.8.0-1007-azure",
     "linux-modules-ipu6-6.8.0-1005-oem",
     "linux-modules-iwlwifi-6.8.0-1005-ibm",
     "linux-modules-iwlwifi-6.8.0-1005-oem",
     "linux-modules-iwlwifi-6.8.0-1007-azure",
     "linux-oem-6.8-headers-6.8.0-1005",
     "linux-oem-6.8-lib-rust-6.8.0-1005-oem",
     "linux-oem-6.8-tools-6.8.0-1005",
     "linux-raspi-realtime",
     "linux-realtime",
     "linux-tools-6.8.0-1005-ibm",
     "linux-tools-6.8.0-1005-oem",
     "linux-tools-6.8.0-1007-azure",
     "linux-udebs-azure"
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
        "os_version": "24.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-azure-6.8",
     "linux-azure-fde",
     "linux-hwe-6.8"
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
