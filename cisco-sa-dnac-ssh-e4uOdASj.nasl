#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207806);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-20350");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi40467");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dnac-ssh-e4uOdASj");
  script_xref(name:"IAVA", value:"2024-A-0591");

  script_name(english:"Cisco Catalyst Center Static SSH Host Key (cisco-sa-dnac-ssh-e4uOdASj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Catalyst Center (formerly Cisco DNA Center) installed on the remote host is prior to 2.3.5.6,
2.3.6.x, or 2.3.7.x prior to 2.3.7.5. It is, therefore, affected by a vulnerability in the SSH server that could allow
an unauthenticated, remote attacker to impersonate a Cisco Catalyst Center appliance. This vulnerability is due to the
presence of a static SSH host key. An attacker could exploit this vulnerability by performing a machine-in-the-middle
attack on SSH connections, which could allow the attacker to intercept traffic between SSH clients and a Cisco Catalyst
Center appliance. A successful exploit could allow the attacker to impersonate the affected appliance, inject commands
into the terminal session, and steal valid user credentials.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dnac-ssh-e4uOdASj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?831c0429");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi40467");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi40467");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20350");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:digital_network_architecture_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_dna_center_web_detect.nbin");
  script_require_keys("installed_sw/Cisco DNA Center");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Cisco DNA Center');

vcf::check_granularity(app_info:app_info, sig_segments:4);
var constraints = [
  {'fixed_version': '2.3.5.6'},
  {'min_version': '2.3.6', 'fixed_version': '2.3.7.5'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
