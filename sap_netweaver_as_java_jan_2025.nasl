#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214335);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2025-0057", "CVE-2025-0067");
  script_xref(name:"IAVA", value:"2025-A-0008");

  script_name(english:"SAP NetWeaver AS Java Multiple Vulnerabilities (January 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"SAP NetWeaver Application Server for Java is affected by multiple vulnerabilities, including the
following:

  - SAP NetWeaver AS JAVA (User Admin Application) is vulnerable to stored cross site scripting 
    vulnerability. An attacker posing as an admin can upload a photo with malicious JS content. When a 
    victim visits the vulnerable component, the attacker can read and modify information within the scope of 
    victim's web browser. (CVE-2025-0057)

  - Due to a missing authorization check on service endpoints in the SAP NetWeaver Application Server Java, 
    an attacker with standard user role can create JCo connection entries, which are used for remote function 
    calls from or to the application server. This could lead to low impact on confidentiality, integrity, and 
    availability of the application. (CVE-2025-0067)

Note that Nessus has not tested for these issue but has instead relied only on the application's self-reported version
number.");
  # https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2025.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67ffb71c");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3514421");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3540108");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0057");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-0067");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('vcf_extras_sap.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::sap_netweaver_as::get_app_info();

var constraints = [
  {'equal' : '7.50', 'fixed_display' : 'See vendor advisory' }
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
