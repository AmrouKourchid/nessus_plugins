#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228971);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-44931");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-44931");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: gpio: prevent potential speculation
    leaks in gpio_device_get_desc() Userspace may trigger a speculative read of an address outside the gpio
    descriptor array. Users can do that by calling gpio_ioctl() with an offset out of range. Offset is copied
    from user and then used as an array index to get the gpio descriptor without sanitization in
    gpio_device_get_desc(). This change ensures that the offset is sanitized by using array_index_nospec() to
    mitigate any possibility of speculative information leaks. This bug was discovered and resolved using
    Coverity Static Analysis Security Testing (SAST) by Synopsys, Inc. (CVE-2024-44931)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44931");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/26");
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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
