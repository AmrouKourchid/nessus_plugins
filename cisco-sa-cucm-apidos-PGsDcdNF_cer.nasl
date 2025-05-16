#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182615);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/18");

  script_cve_id("CVE-2023-20259");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf62074");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-apidos-PGsDcdNF");
  script_xref(name:"IAVA", value:"2023-A-0527");

  script_name(english:"Cisco Emergency Responder DoS (cisco-sa-cucm-apidos-PGsDcdNF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Emergency Responder running on the remote host is affected by
a denial of service (DoS) vulnerability. Due to improper API authentication and incomplete verification of the API
request, an unauthenticated, remote attacker can send a specially crafted HTTP request to a specific API causing a
DoS condition due to high CPU utilization. A successful attack can negatively impact user traffic and management.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-apidos-PGsDcdNF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19b66d72");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf62074");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs  CSCwf62074");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20259");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:emergency_responder");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_voss_emergency_responder_installed.nbin");
  script_require_keys("installed_sw/Cisco Emergency Responder (CER)");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Cisco Emergency Responder (CER)');

var constraints = [
  # https://software.cisco.com/download/home/286328120/type/282074227/release/14SU3
  { 'equal':'14.0.1.13900.34', 'required_cop':'ciscocm.cer_V14SU3_CSCwf62074.cop', 'fixed_display':'Patch ciscocm.cer_V14SU3_CSCwf62074.cop, Bug ID: CSCwf62074' }
];

vcf::cisco_cer::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

