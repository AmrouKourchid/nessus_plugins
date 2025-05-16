#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234620);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id("CVE-2025-20236");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwn07296");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-app-client-rce-ufyMMYLC");
  script_xref(name:"IAVA", value:"2025-A-0287");

  script_name(english:"Cisco Webex App Client-Side RCE (cisco-sa-webex-app-client-rce-ufyMMYLC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex App Client-Side Remote Code Execution is affected by a
vulnerability.

  - A vulnerability in the custom URL parser of Cisco Webex App could allow an unauthenticated, remote
    attacker to persuade a user to download arbitrary files, which could allow the attacker to execute
    arbitrary commands on the host of the targeted user. This vulnerability is due to insufficient input
    validation when Cisco Webex App processes a meeting invite link. An attacker could exploit this
    vulnerability by persuading a user to click a crafted meeting invite link and download arbitrary files. A
    successful exploit could allow the attacker to execute arbitrary commands with the privileges of the
    targeted user. (CVE-2025-20236)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-app-client-rce-ufyMMYLC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86e02dfc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwn07296");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwn07296");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20236");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(829);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_app");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_app_installed.nbin", "cisco_webex_app_mac_installed.nbin");
  script_require_keys("installed_sw/Webex App");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'Webex App', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        { 'min_version' : '44.6', 'fixed_version' : '44.6.2.30589' },
        { 'min_version' : '44.7', 'fixed_version' : '44.8' }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);

