#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232240);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2023-31438");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-31438");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - An issue was discovered in systemd 253. An attacker can truncate a sealed log file and then resume log
    sealing such that checking the integrity shows no error, despite modifications. NOTE: the vendor
    reportedly sent a reply denying that any of the finding was a security vulnerability. (CVE-2023-31438)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31438");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
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
     "libnss-myhostname",
     "libnss-mymachines",
     "libnss-resolve",
     "libnss-systemd",
     "libpam-systemd",
     "libsystemd-dev",
     "libsystemd-shared",
     "libsystemd0",
     "libudev-dev",
     "libudev1",
     "libudev1-udeb",
     "systemd",
     "systemd-boot",
     "systemd-boot-efi",
     "systemd-container",
     "systemd-coredump",
     "systemd-homed",
     "systemd-journal-remote",
     "systemd-oomd",
     "systemd-resolved",
     "systemd-standalone-sysusers",
     "systemd-standalone-tmpfiles",
     "systemd-sysv",
     "systemd-tests",
     "systemd-timesyncd",
     "systemd-userdbd",
     "udev",
     "udev-udeb"
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
     "libnss-myhostname",
     "libnss-mymachines",
     "libnss-resolve",
     "libnss-systemd",
     "libpam-systemd",
     "libsystemd-dev",
     "libsystemd0",
     "libudev-dev",
     "libudev1",
     "libudev1-udeb",
     "systemd",
     "systemd-container",
     "systemd-coredump",
     "systemd-journal-remote",
     "systemd-sysv",
     "systemd-tests",
     "systemd-timesyncd",
     "udev",
     "udev-udeb"
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
     "libnss-myhostname",
     "libnss-mymachines",
     "libnss-resolve",
     "libnss-systemd",
     "libpam-systemd",
     "libsystemd-dev",
     "libsystemd-shared",
     "libsystemd0",
     "libudev-dev",
     "libudev1",
     "systemd",
     "systemd-boot",
     "systemd-boot-efi",
     "systemd-boot-efi-amd64-signed-template",
     "systemd-boot-efi-arm64-signed-template",
     "systemd-container",
     "systemd-coredump",
     "systemd-cryptsetup",
     "systemd-dev",
     "systemd-homed",
     "systemd-journal-remote",
     "systemd-oomd",
     "systemd-repart",
     "systemd-resolved",
     "systemd-standalone-shutdown",
     "systemd-standalone-sysusers",
     "systemd-standalone-tmpfiles",
     "systemd-sysv",
     "systemd-tests",
     "systemd-timesyncd",
     "systemd-ukify",
     "systemd-userdbd",
     "udev"
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
