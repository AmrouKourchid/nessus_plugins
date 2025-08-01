#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180170);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/12");

  script_cve_id("CVE-2023-20201", "CVE-2023-20203", "CVE-2023-20205");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf29121");
  script_xref(name:"CISCO-SA", value:"cisco-sa-pi-epnm-BFjSRJP5");
  script_xref(name:"IAVA", value:"2023-A-0430-S");

  script_name(english:"Cisco Evolved Programmable Network Manager XSS (cisco-sa-pi-epnm-BFjSRJP5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Evolved Programmable Network Manager installed on the remote host is prior to 7.1. It is,
therefore, affected by a cross-site scripting (XSS) vulnerability. Due to insufficient validation of user input, an
authenticated, remote attacker can, by persuading a user of the affected interface to view a specially crafted page,
execute malicious HTML or script content in the context of the user.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-pi-epnm-BFjSRJP5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a34a4672");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf29121");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf29121");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20205");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:evolved_programmable_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_epn_manager_detect.nbin");
  script_require_keys("installed_sw/Cisco EPN Manager");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Cisco EPN Manager');

var constraints = [
  {'fixed_version': '7.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
