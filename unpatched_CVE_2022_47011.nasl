#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225075);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-47011");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-47011");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - An issue was discovered function parse_stab_struct_fields in stabs.c in Binutils 2.34 thru 2.38, allows
    attackers to cause a denial of service due to memory leaks. (CVE-2022-47011)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-47011");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
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
     "binutils",
     "binutils-aarch64-linux-gnu",
     "binutils-aarch64-linux-gnu-dbg",
     "binutils-alpha-linux-gnu",
     "binutils-alpha-linux-gnu-dbg",
     "binutils-arm-linux-gnueabi",
     "binutils-arm-linux-gnueabi-dbg",
     "binutils-arm-linux-gnueabihf",
     "binutils-arm-linux-gnueabihf-dbg",
     "binutils-common",
     "binutils-dev",
     "binutils-doc",
     "binutils-for-build",
     "binutils-for-host",
     "binutils-hppa-linux-gnu",
     "binutils-hppa-linux-gnu-dbg",
     "binutils-hppa64-linux-gnu",
     "binutils-hppa64-linux-gnu-dbg",
     "binutils-i686-linux-gnu",
     "binutils-i686-linux-gnu-dbg",
     "binutils-ia64-linux-gnu",
     "binutils-ia64-linux-gnu-dbg",
     "binutils-m68k-linux-gnu",
     "binutils-m68k-linux-gnu-dbg",
     "binutils-multiarch",
     "binutils-multiarch-dbg",
     "binutils-multiarch-dev",
     "binutils-powerpc64le-linux-gnu",
     "binutils-powerpc64le-linux-gnu-dbg",
     "binutils-s390x-linux-gnu",
     "binutils-s390x-linux-gnu-dbg",
     "binutils-source",
     "binutils-x86-64-linux-gnu",
     "binutils-x86-64-linux-gnu-dbg",
     "libbinutils",
     "libbinutils-dbg",
     "libctf-nobfd0",
     "libctf-nobfd0-dbg",
     "libctf0",
     "libctf0-dbg"
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
     "binutils",
     "gcc-toolset-13-gdb",
     "gdb"
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
        "os_version": "8"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "binutils",
     "gdb"
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
