#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232018);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2013-4472");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2013-4472");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - The openTempFile function in goo/gfile.cc in Xpdf and Poppler 0.24.3 and earlier, when running on a system
    other than Unix, allows local users to overwrite arbitrary files via a symlink attack on temporary files
    with predictable names. (CVE-2013-4472)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4472");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/26");
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
     "gir1.2-poppler-0.18",
     "libpoppler-cpp-dev",
     "libpoppler-cpp0v5",
     "libpoppler-dev",
     "libpoppler-glib-dev",
     "libpoppler-glib-doc",
     "libpoppler-glib8",
     "libpoppler-private-dev",
     "libpoppler-qt5-1",
     "libpoppler-qt5-dev",
     "libpoppler-qt6-3",
     "libpoppler-qt6-dev",
     "libpoppler126",
     "poppler-utils",
     "xpdf"
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
     "gir1.2-poppler-0.18",
     "libpoppler-cpp-dev",
     "libpoppler-cpp0v5",
     "libpoppler-dev",
     "libpoppler-glib-dev",
     "libpoppler-glib-doc",
     "libpoppler-glib8",
     "libpoppler-private-dev",
     "libpoppler-qt5-1",
     "libpoppler-qt5-dev",
     "libpoppler102",
     "poppler-utils",
     "xpdf"
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
     "gir1.2-poppler-0.18",
     "libpoppler-cpp-dev",
     "libpoppler-cpp2",
     "libpoppler-dev",
     "libpoppler-glib-dev",
     "libpoppler-glib-doc",
     "libpoppler-glib8t64",
     "libpoppler-private-dev",
     "libpoppler-qt5-1t64",
     "libpoppler-qt5-dev",
     "libpoppler-qt6-3t64",
     "libpoppler-qt6-dev",
     "libpoppler145",
     "poppler-utils",
     "xpdf"
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
