#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190353);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/19");

  script_cve_id("CVE-2024-20252", "CVE-2024-20254", "CVE-2024-20255");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa25074");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa25099");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa25100");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-csrf-KnnZDMj3");
  script_xref(name:"IAVA", value:"2024-A-0076-S");

  script_name(english:"Cisco Expressway Series XSRF (cisco-sa-expressway-csrf-KnnZDMj3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Expressway Series is affected by multiple vulnerabilities.

  - A vulnerability in Cisco Expressway Series and Cisco TelePresence Video Communication Server
    (VCS) could allow an unauthenticated, remote attacker to conduct cross-site request forgery (CSRF) attacks
    that perform arbitrary actions on an affected device. Note: Cisco Expressway Series refers to Cisco
    Expressway Control (Expressway-C) devices and Cisco Expressway Edge (Expressway-E) devices. For more
    information about these vulnerabilities, see the Details [#details] section of this advisory.
    (CVE-2024-20252, CVE-2024-20254)

  - A vulnerability in the SOAP API of Cisco Expressway Series and Cisco TelePresence Video Communication
    Server could allow an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF)
    attack on an affected system. This vulnerability is due to insufficient CSRF protections for the web-based
    management interface of an affected system. An attacker could exploit this vulnerability by persuading a
    user of the REST API to follow a crafted link. A successful exploit could allow the attacker to cause the
    affected system to reload. (CVE-2024-20255)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-csrf-KnnZDMj3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?971fa3eb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa25074");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa25099");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa25100");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwa25074, CSCwa25099, CSCwa25100");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/09");

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
  { 'min_ver':'0.0', 'fix_ver' : '14.3.4' }
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'flags'         , {'xsrf':TRUE},
  'bug_id'        , 'CSCwa25074, CSCwa25099, CSCwa25100',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
