#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182579);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id("CVE-2023-20108");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy16642");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-imp-dos-49GL7rzT");
  script_xref(name:"IAVA", value:"2023-A-0432");

  script_name(english:"Cisco Unified Communications Manager IM & Presence DoS (cisco-sa-cucm-imp-dos-49GL7rzT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Communications IM & Presence Services installed on the remote host is prior to 12.5(1)SU7
or 14 prior to 14SU3. It is, therefore affected by a denial of service (DoS) vulnerability. Due to improper validation
of user-supplied input, an unauthenticated, remote attacker can send a specially crafted login message causing the
affected device to restart.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-imp-dos-49GL7rzT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e384f708");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy16642");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy16642");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20108");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_cucm_imp_detect.nbin");
  script_require_keys("installed_sw/Cisco Unified CM IM&P");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco Unified CM IM&P');

var constraints = [
  # https://software.cisco.com/download/home/286322282/type/282074312/release/12.5(1)SU7
  { 'min_version': '12.5.1', 'fixed_version': '12.5.1.17900.7', 'fixed_display': '12.5(1)SU7' },
  # https://software.cisco.com/download/home/286328299/type/282074312/release/14SU3
  { 'min_version' : '14.0',  'fixed_version' : '14.0.1.13900.8', 'fixed_display': '14SU3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

