#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200219);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/10");

  script_cve_id("CVE-2024-20360");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf92182");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-sqli-WFFDnNOs");

  script_name(english:"Cisco Firepower Management Center Software SQL Injection (cisco-sa-fmc-sqli-WFFDnNOs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco Firepower Management Center (FMC) Software could allow
an authenticated, remote attacker to conduct SQL injection attacks on an affected system. This vulnerability exists 
because the web-based management interface does not adequately validate user input. An attacker could exploit this 
vulnerability by authenticating to the application and sending crafted SQL queries to an affected system. A successful 
exploit could allow the attacker to obtain any data from the database, execute arbitrary commands on the underlying 
operating system, and elevate privileges to root. To exploit this vulnerability, an attacker would need at least 
Read Only user credentials.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-sqli-WFFDnNOs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee98bc27");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf92182");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf92182");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20360");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(
  app:'Cisco Firepower Management Center',
  kb_ver:'Host/Cisco/firepower_mc/version'
);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'min_version':'7.0', 'fixed_version':'7.0.6.1'},
  {'min_version':'7.1', 'fixed_version':'7.2.5.1', 'fixed_display':'7.2.5.1 / 7.2.6'},
  {'min_version':'7.3', 'fixed_version':'7.4.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
