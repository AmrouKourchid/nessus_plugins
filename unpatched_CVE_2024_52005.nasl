#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231817);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-52005");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-52005");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - Git is a source code management tool. When cloning from a server (or fetching, or pushing), informational
    or error messages are transported from the remote Git process to the client via the so-called sideband
    channel. These messages will be prefixed with remote: and printed directly to the standard error
    output. Typically, this standard error output is connected to a terminal that understands ANSI escape
    sequences, which Git did not protect against. Most modern terminals support control sequences that can be
    used by a malicious actor to hide and misrepresent information, or to mislead the user into executing
    untrusted scripts. As requested on the git-security mailing list, the patches are under discussion on the
    public mailing list. Users are advised to update as soon as possible. Users unable to upgrade should avoid
    recursive clones unless they are from trusted sources. (CVE-2024-52005)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52005");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
     "git",
     "git-all",
     "git-cvs",
     "git-daemon-run",
     "git-daemon-sysvinit",
     "git-doc",
     "git-el",
     "git-email",
     "git-gui",
     "git-man",
     "git-mediawiki",
     "git-svn",
     "gitk",
     "gitweb"
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
       "match_one": {
        "os_version": [
         "18.04",
         "20.04"
        ]
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "git",
     "git-all",
     "git-cvs",
     "git-daemon-run",
     "git-daemon-sysvinit",
     "git-doc",
     "git-email",
     "git-gui",
     "git-man",
     "git-mediawiki",
     "git-svn",
     "gitk",
     "gitweb"
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
       "match_one": {
        "os_version": [
         "22.04",
         "24.04",
         "24.10"
        ]
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "git",
     "git-all",
     "git-arch",
     "git-core",
     "git-cvs",
     "git-daemon-run",
     "git-daemon-sysvinit",
     "git-doc",
     "git-el",
     "git-email",
     "git-gui",
     "git-man",
     "git-mediawiki",
     "git-svn",
     "gitk",
     "gitweb"
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
    "name": "git",
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
         "7",
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
