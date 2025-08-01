#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230756);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2025-1178");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2025-1178");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - A vulnerability was found in GNU Binutils 2.43. It has been declared as problematic. Affected by this
    vulnerability is the function bfd_putl64 of the file libbfd.c of the component ld. The manipulation leads
    to memory corruption. The attack can be launched remotely. The complexity of an attack is rather high. The
    exploitation appears to be difficult. The exploit has been disclosed to the public and may be used. The
    identifier of the patch is 75086e9de1707281172cc77f178e7949a4414ed0. It is recommended to apply a patch to
    fix this issue. (CVE-2025-1178)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1178");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
     "binutils-arc-linux-gnu",
     "binutils-arc-linux-gnu-dbg",
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
     "libctf0-dbg",
     "libgprofng0",
     "libgprofng0-dbg"
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
     "binutils-aarch64-linux-gnu",
     "binutils-aarch64-linux-gnu-dbg",
     "binutils-alpha-linux-gnu",
     "binutils-alpha-linux-gnu-dbg",
     "binutils-arc-linux-gnu",
     "binutils-arc-linux-gnu-dbg",
     "binutils-arm-linux-gnueabi",
     "binutils-arm-linux-gnueabi-dbg",
     "binutils-arm-linux-gnueabihf",
     "binutils-arm-linux-gnueabihf-dbg",
     "binutils-common",
     "binutils-dbg",
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
     "libctf0-dbg",
     "libgprofng0",
     "libgprofng0-dbg",
     "libsframe1",
     "libsframe1-dbg"
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
    "name": "mingw-binutils",
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
