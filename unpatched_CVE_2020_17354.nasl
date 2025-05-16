#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(223426);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/04");

  script_cve_id("CVE-2020-17354");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2020-17354");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - LilyPond before 2.24 allows attackers to bypass the -dsafe protection mechanism via output-def-lookup or
    output-def-scope, as demonstrated by dangerous Scheme code in a .ly file that causes arbitrary code
    execution during conversion to a different file format. NOTE: in 2.24 and later versions, safe mode is
    removed, and the product no longer tries to block code execution when external files are used.
    (CVE-2020-17354)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17354");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/04");

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
     "lilypond",
     "lilypond-data",
     "lilypond-doc",
     "lilypond-doc-html",
     "lilypond-doc-html-ca",
     "lilypond-doc-html-cs",
     "lilypond-doc-html-de",
     "lilypond-doc-html-es",
     "lilypond-doc-html-fr",
     "lilypond-doc-html-hu",
     "lilypond-doc-html-it",
     "lilypond-doc-html-ja",
     "lilypond-doc-html-nl",
     "lilypond-doc-html-pt",
     "lilypond-doc-html-zh",
     "lilypond-doc-pdf",
     "lilypond-doc-pdf-ca",
     "lilypond-doc-pdf-de",
     "lilypond-doc-pdf-es",
     "lilypond-doc-pdf-fr",
     "lilypond-doc-pdf-hu",
     "lilypond-doc-pdf-it",
     "lilypond-doc-pdf-nl",
     "lilypond-doc-pdf-pt",
     "lilypond-fonts"
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
