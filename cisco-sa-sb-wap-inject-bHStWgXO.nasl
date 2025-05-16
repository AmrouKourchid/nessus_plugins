#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188066);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/29");

  script_cve_id("CVE-2024-20287");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi22632");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-wap-inject-bHStWgXO");

  script_name(english:"Cisco WAP371 Wireless Access Point Command Injection (cisco-sa-sb-wap-inject-bHStWgXO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco WAP371 Wireless Access Point Command Injection is affected by a
vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-wap-inject-bHStWgXO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18a41054");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi22632");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi22632");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20287");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wap371");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_wap_detect.nbin");
  script_require_keys("installed_sw/Cisco Small Business Wireless Access Point");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');

var app_name = 'Cisco Small Business Wireless Access Point'; 
var app_info = vcf::combined_get_app_info(app:app_name); 

display(app_info, '\n');

if (app_info['Model'] != 'WAP371')
  audit(AUDIT_INST_VER_NOT_VULN, app_name, app_info['Model']);

var constraints = [
  {'min_version' : '0.0', 'max_version' : '9999.9999.9999.9999', 'fixed_display' : 'See vendor advisory'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , app_info['version'],
  'bug_id'        , 'CSCwi22632',
  'disable_caveat', TRUE
);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);