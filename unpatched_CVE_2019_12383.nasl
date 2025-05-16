#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232039);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2019-12383");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2019-12383");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - Tor Browser before 8.0.1 has an information exposure vulnerability. It allows remote attackers to detect
    the browser's UI locale by measuring a button width, even if the user has a Don't send my language
    setting. (CVE-2019-12383)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12383");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/21");
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
     "firefox-esr",
     "firefox-esr-l10n-ach",
     "firefox-esr-l10n-af",
     "firefox-esr-l10n-all",
     "firefox-esr-l10n-an",
     "firefox-esr-l10n-ar",
     "firefox-esr-l10n-ast",
     "firefox-esr-l10n-az",
     "firefox-esr-l10n-be",
     "firefox-esr-l10n-bg",
     "firefox-esr-l10n-bn",
     "firefox-esr-l10n-br",
     "firefox-esr-l10n-bs",
     "firefox-esr-l10n-ca",
     "firefox-esr-l10n-ca-valencia",
     "firefox-esr-l10n-cak",
     "firefox-esr-l10n-cs",
     "firefox-esr-l10n-cy",
     "firefox-esr-l10n-da",
     "firefox-esr-l10n-de",
     "firefox-esr-l10n-dsb",
     "firefox-esr-l10n-el",
     "firefox-esr-l10n-en-ca",
     "firefox-esr-l10n-en-gb",
     "firefox-esr-l10n-eo",
     "firefox-esr-l10n-es-ar",
     "firefox-esr-l10n-es-cl",
     "firefox-esr-l10n-es-es",
     "firefox-esr-l10n-es-mx",
     "firefox-esr-l10n-et",
     "firefox-esr-l10n-eu",
     "firefox-esr-l10n-fa",
     "firefox-esr-l10n-ff",
     "firefox-esr-l10n-fi",
     "firefox-esr-l10n-fr",
     "firefox-esr-l10n-fur",
     "firefox-esr-l10n-fy-nl",
     "firefox-esr-l10n-ga-ie",
     "firefox-esr-l10n-gd",
     "firefox-esr-l10n-gl",
     "firefox-esr-l10n-gn",
     "firefox-esr-l10n-gu-in",
     "firefox-esr-l10n-he",
     "firefox-esr-l10n-hi-in",
     "firefox-esr-l10n-hr"
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
       "match_one": {
        "os_version": [
         "11",
         "12",
         "13"
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
