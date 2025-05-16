#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229920);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2020-24352");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2020-24352");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - An issue was discovered in QEMU through 5.1.0. An out-of-bounds memory access was found in the ATI VGA
    device implementation. This flaw occurs in the ati_2d_blt() routine in hw/display/ati_2d.c while handling
    MMIO write operations through the ati_mm_write() callback. A malicious guest could use this flaw to crash
    the QEMU process on the host, resulting in a denial of service. (CVE-2020-24352)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24352");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
     "qemu-block-extra",
     "qemu-guest-agent",
     "qemu-system",
     "qemu-system-arm",
     "qemu-system-common",
     "qemu-system-data",
     "qemu-system-gui",
     "qemu-system-mips",
     "qemu-system-misc",
     "qemu-system-ppc",
     "qemu-system-sparc",
     "qemu-system-x86",
     "qemu-system-xen",
     "qemu-user",
     "qemu-user-binfmt",
     "qemu-user-static",
     "qemu-utils"
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
     "qemu",
     "qemu-block-extra",
     "qemu-guest-agent",
     "qemu-system",
     "qemu-system-arm",
     "qemu-system-common",
     "qemu-system-data",
     "qemu-system-gui",
     "qemu-system-mips",
     "qemu-system-misc",
     "qemu-system-ppc",
     "qemu-system-sparc",
     "qemu-system-x86",
     "qemu-user",
     "qemu-user-binfmt",
     "qemu-user-static",
     "qemu-utils"
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
  },
  {
   "product": {
    "name": [
     "qemu-block-extra",
     "qemu-guest-agent",
     "qemu-system",
     "qemu-system-arm",
     "qemu-system-common",
     "qemu-system-data",
     "qemu-system-gui",
     "qemu-system-mips",
     "qemu-system-misc",
     "qemu-system-modules-opengl",
     "qemu-system-modules-spice",
     "qemu-system-ppc",
     "qemu-system-riscv",
     "qemu-system-s390x",
     "qemu-system-sparc",
     "qemu-system-x86",
     "qemu-system-xen",
     "qemu-user",
     "qemu-user-binfmt",
     "qemu-user-static",
     "qemu-utils"
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
        "os_version": "13"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "qemu-kvm",
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
