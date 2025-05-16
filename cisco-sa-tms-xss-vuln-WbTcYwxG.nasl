#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233777);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_cve_id("CVE-2025-20208");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj66927");
  script_xref(name:"CISCO-SA", value:"cisco-sa-tms-xss-vuln-WbTcYwxG");

  script_name(english:"Cisco TelePresence Management Suite XSS (cisco-sa-tms-xss-vuln-WbTcYwxG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco TelePresence Management Suite is affected by a cross-site scripting
vulnerability.

  - A vulnerability in the web-based management interface of Cisco TelePresence Management Suite (TMS) could
    allow a low-privileged, remote attacker to conduct a cross-site scripting (XSS) attack against a user of
    the interface. This vulnerability is due to insufficient input validation by the web-based management
    interface. An attacker could exploit this vulnerability by inserting malicious data in a specific data
    field in the interface. A successful exploit could allow the attacker to execute arbitrary script code in
    the context of the affected interface or access sensitive, browser-based information. (CVE-2025-20208)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tms-xss-vuln-WbTcYwxG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df92a9da");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj66927");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwj66927");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20208");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_management_suite");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_management_suite_detect.nbin", "cisco_telepresence_management_suite_installed.nbin");
  script_require_keys("installed_sw/Cisco Telepresence Management Suite");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Cisco Telepresence Management Suite');

var constraints = [{'equal':'15.13.6', 'fixed_display':'See vendor advisory'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);

