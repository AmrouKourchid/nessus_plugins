#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216270);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id("CVE-2023-24527", "CVE-2024-22126", "CVE-2025-24869");
  script_xref(name:"IAVA", value:"2025-A-0112");

  script_name(english:"SAP NetWeaver AS Java Multiple Vulnerabilities (Feb 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"SAP NetWeaver Application Server for Java is affected by multiple vulnerabilities, including the
following:

  - The User Admin application of SAP NetWeaver AS for Java insufficiently validates and improperly encodes the
    incoming URL parameters before including them into the redirect URL. This results in Cross-Site Scripting
    (XSS) vulnerability, leading to a high impact on confidentiality and mild impact on integrity and availability.
    This vulnerability was reported and a initial patch was provided in 2024, but that patch is considered obsolete
    and is fully fixed with the patch released in Febuary of 2025.
    (CVE-2024-22126)

  - SAP NetWeaver AS Java (Deploy Service) does not perform any access control checks for functionalities that 
    require user identity enabling an unauthenticated attacker to attach to an open interface and make use of an 
    open naming and directory api to access a service which will enable them to access but not modify server 
    settings and data (CVE-2023-24527)

  - SAP NetWeaver AS Java (Application Server Java) allows an attacker to access an endpoint that can disclose 
    information about deployed server components, including their XML definitions. This information should ideally 
    be restricted to customer administrators, even though they may not need it. These XML files are not entirely 
    SAP-internal as they are deployed with the server. In such a scenario, sensitive information could be exposed 
    (CVE-2025-24869)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.sap.com/en/my-support/knowledge-base/security-notes-news/february-2025.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1505493e");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3550027");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3287784");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3557138");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3417627");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22126");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/14");

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
  flags:{xss:TRUE}
);
