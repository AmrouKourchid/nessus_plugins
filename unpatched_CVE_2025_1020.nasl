#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230491);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2025-1020");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2025-1020");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - Memory safety bugs present in Firefox 134 and Thunderbird 134. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. This vulnerability affects Firefox < 135 and Thunderbird < 135. (CVE-2025-1020)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1020");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
     "thunderbird",
     "thunderbird-dbg",
     "thunderbird-dev",
     "thunderbird-gnome-support",
     "thunderbird-gnome-support-dbg",
     "thunderbird-locale-af",
     "thunderbird-locale-ar",
     "thunderbird-locale-ast",
     "thunderbird-locale-be",
     "thunderbird-locale-bg",
     "thunderbird-locale-bn",
     "thunderbird-locale-bn-bd",
     "thunderbird-locale-br",
     "thunderbird-locale-ca",
     "thunderbird-locale-cak",
     "thunderbird-locale-cs",
     "thunderbird-locale-cy",
     "thunderbird-locale-da",
     "thunderbird-locale-de",
     "thunderbird-locale-dsb",
     "thunderbird-locale-el",
     "thunderbird-locale-en-gb",
     "thunderbird-locale-en-us",
     "thunderbird-locale-es-ar",
     "thunderbird-locale-es-es",
     "thunderbird-locale-fy-nl",
     "thunderbird-locale-ga-ie",
     "thunderbird-locale-nb-no",
     "thunderbird-locale-nn-no",
     "thunderbird-locale-pa-in",
     "thunderbird-locale-pt-br",
     "thunderbird-locale-pt-pt",
     "thunderbird-locale-sv-se",
     "thunderbird-locale-ta-lk",
     "thunderbird-locale-zh-cn",
     "thunderbird-locale-zh-tw",
     "thunderbird-mozsymbols",
     "xul-ext-calendar-timezones",
     "xul-ext-gdata-provider",
     "xul-ext-lightning"
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
         "20.04",
         "22.04"
        ]
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
