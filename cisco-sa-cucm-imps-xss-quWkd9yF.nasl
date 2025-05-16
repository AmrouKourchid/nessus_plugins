#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192937);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/05");

  script_cve_id("CVE-2024-20310");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf41335");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-imps-xss-quWkd9yF");
  script_xref(name:"IAVA", value:"2024-A-0197");

  script_name(english:"Cisco Unified Communications Manager IM & Presence XSS (cisco-sa-cucm-imps-xss-quWkd9yF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager IM & Presence running on the report host
is affected by a coss-site scripting (XSS) vulnerability. The vulnerability exists in the web-based management interface
due to improper validation of user-supplied input before returning it to users. An unauthenticated, remote attacker can
exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's browser
session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-imps-xss-quWkd9yF
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?87c38451");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf41335");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf41335");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20310");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_cucm_imp_detect.nbin");
  script_require_keys("installed_sw/Cisco Unified CM IM&P");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco Unified CM IM&P');

var constraints = [
  # https://software.cisco.com/download/home/286322282/type/282074312/release/12.5(1)SU8
  { 'fixed_version': '12.5.1.18900.6', 'fixed_display': '12.5(1)SU8' },
  # https://software.cisco.com/download/home/286328299/type/282074312/release/14SU3
  { 'min_version': '14.0', 'max_version' : '14.0.1.13900.8', 'fixed_display': '14SU4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
