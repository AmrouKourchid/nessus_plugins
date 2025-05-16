#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205318);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/12");

  script_cve_id(
    "CVE-2024-32862",
    "CVE-2024-32863",
    "CVE-2024-32864",
    "CVE-2024-32931"
  );
  script_xref(name:"ICSA", value:"24-214-02");
  script_xref(name:"ICSA", value:"24-214-03");
  script_xref(name:"ICSA", value:"24-214-04");
  script_xref(name:"ICSA", value:"24-214-06");

  script_name(english:"Johnson Controls exacqVision Web Service < 24.06 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web application for video management is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Johnson Controls exacqVision Web Service running on the remote host is prior to 24.03. It is, 
therefore, affected by multiple vulnerabilities.

  - Under certain circumstances the exacqVision Web Services does not provide sufficient protection from
  untrusted domains. (CVE-2024-32862)

  - Under certain circumstances the exacqVision Web Services may be susceptible to Cross-Site Request Forgery 
  (CSRF). (CVE-2024-32863)

  - Under certain circumstances the exacqVision Web Services will not enforce secure web communications 
  (HTTPS). (CVE-2024-32864)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?add56de2");
  script_set_attribute(attribute:"solution", value:
"Upgrade exacqVision Web Service to version 24.06 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32863");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:johnsoncontrols:exacqvision_web_service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SCADA");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("exacqVision_web_service_detect.nbin");
  script_require_keys("installed_sw/Johnson Controls exacqVision Web Service");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app = 'Johnson Controls exacqVision Web Service';

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  {'fixed_version': '24.06'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);