#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213081);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id(
    "CVE-2024-47578",
    "CVE-2024-47579",
    "CVE-2024-47580",
    "CVE-2024-47582"
  );

  script_name(english:"SAP NetWeaver AS Java Multiple Vulnerabilities (December 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"SAP NetWeaver Application Server for Java is affected by multiple vulnerabilities, including the
following:

  - Adobe Document Service allows an attacker with administrator privileges to send a crafted request from a 
    vulnerable web application. It is usually used to target internal systems behind firewalls that are 
    normally inaccessible to an attacker from the external network, resulting in a Server-Side Request 
    Forgery vulnerability. On successful exploitation, the attacker can read or modify any file and/or make 
    the entire system unavailable. (CVE-2024-47578)

  - An attacker authenticated as an administrator can use an exposed webservice to upload or download a 
    custom PDF font file on the system server. Using the upload functionality to copy an internal file into 
    a font file and subsequently using the download functionality to retrieve that file allows the attacker 
    to read any file on the server with no effect on integrity or availability. (CVE-2024-47579)

  - An attacker authenticated as an administrator can use an exposed webservice to create a PDF with an 
    embedded attachment. By specifying the file to be an internal server file and subsequently downloading 
    the generated PDF, the attacker can read any file on the server with no effect on integrity or 
    availability. (CVE-2024-47580)

  - Due to missing validation of XML input, an unauthenticated attacker could send malicious input to an 
    endpoint which leads to XML Entity Expansion attack. This causes limited impact on availability of the 
    application. (CVE-2024-47582)

Note that Nessus has not tested for these issue but has instead relied only on the application's self-reported version
number.");
  # https://support.sap.com/en/my-support/knowledge-base/security-notes-news/december-2024.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71bf9e22");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3536965");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3351041");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47578");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
