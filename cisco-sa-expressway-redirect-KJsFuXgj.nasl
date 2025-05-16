#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202695);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/13");

  script_cve_id("CVE-2024-20400");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa25104");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-redirect-KJsFuXgj");
  script_xref(name:"IAVA", value:"2024-A-0413-S");

  script_name(english:"Cisco Expressway Series Open Redirect (cisco-sa-expressway-redirect-KJsFuXgj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Expressway Series Open Redirect is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco Expressway Series could allow an
    unauthenticated, remote attacker to redirect a user to a malicious web page. This vulnerability is due to
    improper input validation of HTTP request parameters. An attacker could exploit this vulnerability by
    intercepting and modifying an HTTP request from a user. A successful exploit could allow the attacker to
    redirect the user to a malicious web page. Note: Cisco Expressway Series refers to Cisco Expressway
    Control (Expressway-C) devices and Cisco Expressway Edge (Expressway-E) devices.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-redirect-KJsFuXgj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cef7247");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa25104");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa25104");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20400");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(601);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');

var vuln_ranges = [
  { 'min_ver':'0.0', 'fix_ver' : '15.0.2' }
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwa25104',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
