#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226429);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2023-52488");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52488");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: serial: sc16is7xx: convert from _raw_
    to _noinc_ regmap functions for FIFO The SC16IS7XX IC supports a burst mode to access the FIFOs where the
    initial register address is sent ($00), followed by all the FIFO data without having to resend the
    register address each time. In this mode, the IC doesn't increment the register address for each R/W byte.
    The regmap_raw_read() and regmap_raw_write() are functions which can perform IO over multiple registers.
    They are currently used to read/write from/to the FIFO, and although they operate correctly in this burst
    mode on the SPI bus, they would corrupt the regmap cache if it was not disabled manually. The reason is
    that when the R/W size is more than 1 byte, these functions assume that the register address is
    incremented and handle the cache accordingly. Convert FIFO R/W functions to use the regmap _noinc_
    versions in order to remove the manual cache control which was a workaround when using the _raw_ versions.
    FIFO registers are properly declared as volatile so cache will not be used/updated for FIFO accesses.
    (CVE-2023-52488)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52488");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/29");
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
    "name": [
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
    "name": "linux-gkeop",
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
