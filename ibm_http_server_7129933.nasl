#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(191707);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2023-52425");
  script_xref(name:"IAVB", value:"2024-B-0019");

  script_name(english:"IBM HTTP Server 8.5.0.0 < 8.5.5.26 / 9.0.0.0 < 9.0.5.18 DoS (7129933)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by a denaial of service vulnerability.

 - libexpat is vulnerable to a denial of service, caused by improper system
   resource allocation. By sending a specially crafted request using an overly
   large token, a remote attacker could exploit this vulnerability to cause a
   denial of service. (CVE-2023-5245)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.ibm.com/support/pages/security-bulletin-ibm-http-server-vulnerable-denial-service-due-libexpat-cve-2023-52425
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8349f800");
  #https://www.ibm.com/support/pages/node/7129840
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5978432c");
  script_set_attribute(attribute:"solution", value:
"Update to IBM WebSphere Application Server version 8.5.5.26, 9.0.5.19 or later. Alternatively, upgrade to the minimal fix pack 
levels required by the interim fix and then apply Interim Fix PH59697 (refer to vendor advisory).");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52425");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_http_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM HTTP Server (IHS)");

  exit(0);
}


include('vcf.inc');

var app = 'IBM HTTP Server (IHS)';
var fix = 'Interim Fix PH59697';

var app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PH59697' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

var constraints = [
  { 'min_version' : '8.0.5.0', 'fixed_version' : '8.5.5.26', 'fixed_display' : '8.5.5.26 or ' + fix },
  { 'min_version' : '9.0.0.0', 'fixed_version' : '9.0.5.19', 'fixed_display' : '9.0.5.19 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
