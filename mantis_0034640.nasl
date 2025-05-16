#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208073);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id("CVE-2024-45792");
  script_xref(name:"IAVB", value:"2024-B-0144");

  script_name(english:"MantisBT < 2.26.4 Information Disclosure (0034640)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of MantisBT installed on the remote host is prior to 2.26.4. It is, therefore, affected by a information 
disclosure vulnerability as referenced in the 0034640 advisory.

  - Mantis Bug Tracker (MantisBT) is an open source issue tracker. Using a crafted POST request, an
    unprivileged, registered user is able to retrieve information about other users' personal system profiles.
    This vulnerability is fixed in 2.26.4. (CVE-2024-45792)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/mantisbt/mantisbt/security/advisories/GHSA-h5q3-fjp4-2x7r
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4af82ac");
  # https://github.com/mantisbt/mantisbt/commit/ef0f820284032350cc20a39ff9cb2010d5463b41
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98e4dc82");
  script_set_attribute(attribute:"see_also", value:"https://mantisbt.org/bugs/view.php?id=34640");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MantisBT version 2.26.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45792");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mantisbt_detect.nbin");
  script_require_keys("installed_sw/MantisBT");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http.inc");
include("vcf.inc");

var app = "MantisBT";

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [ { 'fixed_version' : '2.26.4' }];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
