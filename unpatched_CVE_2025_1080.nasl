#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232168);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2025-1080");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2025-1080");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - LibreOffice supports Office URI Schemes to enable browser integration of LibreOffice with MS SharePoint
    server. An additional scheme 'vnd.libreoffice.command' specific to LibreOffice was added. In the affected
    versions of LibreOffice a link in a browser using that scheme could be constructed with an embedded inner
    URL that when passed to LibreOffice could call internal macros with arbitrary arguments. This issue
    affects LibreOffice: from 24.8 before < 24.8.5, from 25.2 before < 25.2.1. (CVE-2025-1080)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1080");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/04");
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
     "libofficebean-java",
     "libreoffice",
     "libreoffice-base",
     "libreoffice-base-core",
     "libreoffice-base-drivers",
     "libreoffice-base-nogui",
     "libreoffice-calc",
     "libreoffice-calc-nogui",
     "libreoffice-common",
     "libreoffice-core",
     "libreoffice-core-nogui",
     "libreoffice-draw",
     "libreoffice-draw-nogui",
     "libreoffice-gnome",
     "libreoffice-help-common",
     "libreoffice-impress",
     "libreoffice-impress-nogui",
     "libreoffice-java-common",
     "libreoffice-l10n-af",
     "libreoffice-l10n-am",
     "libreoffice-l10n-in",
     "libreoffice-l10n-za",
     "libreoffice-math",
     "libreoffice-math-nogui",
     "libreoffice-nogui",
     "libreoffice-officebean",
     "libreoffice-script-provider-bsh",
     "libreoffice-script-provider-js",
     "libreoffice-script-provider-python",
     "libreoffice-sdbc-hsqldb",
     "libreoffice-sdbc-mysql",
     "libreoffice-style-breeze",
     "libreoffice-style-colibre",
     "libreoffice-style-elementary",
     "libreoffice-style-karasa-jaga",
     "libreoffice-style-sifr",
     "libreoffice-style-sukapura",
     "libreoffice-writer",
     "libreoffice-writer-nogui",
     "libunoil-java",
     "python3-access2base",
     "python3-uno"
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
