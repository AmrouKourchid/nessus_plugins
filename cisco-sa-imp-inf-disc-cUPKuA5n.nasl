#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215006);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id("CVE-2024-20457");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk31853");
  script_xref(name:"CISCO-SA", value:"cisco-sa-imp-inf-disc-cUPKuA5n");
  script_xref(name:"IAVA", value:"2024-A-0712");

  script_name(english:"Cisco Unified Communications Manager IM & Presence Information Disclosure (cisco-sa-imp-inf-disc-cUPKuA5n)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager IM & Presence running on the remote host
is affected by an information disclosure vulnerability in the logging component. This could allow an authenticated, 
remote attacker to view sensitive information in clear text on an affected system. This vulnerability is due to the 
storage of unencrypted credentials in certain logs. An attacker could exploit this vulnerability by accessing the logs 
on an affected system and obtaining credentials that they may not normally have access to. A successful exploit could 
allow the attacker to access sensitive information from the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-imp-inf-disc-cUPKuA5n
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7df57015");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk31853");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk31853");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20457");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_cucm_imp_detect.nbin");
  script_require_keys("installed_sw/Cisco Unified CM IM&P");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco Unified CM IM&P');

var constraints = [
  # https://software.cisco.com/download/home/286322282/type/282074312/release/12.5(1)SU9
  { 'fixed_version': '12.5.1.21900.3', 'fixed_display': '12.5(1)SU9' },
  # https://software.cisco.com/download/home/286328299/type/282074312/release/14SU4
  { 'min_version': '14.0', 'max_version' : '14.0.1.14900.4', 'fixed_display': '14SU5' },
  # https://software.cisco.com/download/home/286331963/type/282074312/release/15SU2
  { 'min_version': '15.0', 'fixed_version' : '15.0.1.12900.10', 'fixed_display': '15SU2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
