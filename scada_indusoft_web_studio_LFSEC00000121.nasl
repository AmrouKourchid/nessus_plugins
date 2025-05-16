#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104101);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/15 20:50:24");

  script_cve_id("CVE-2017-13997");
  script_xref(name:"ICSA", value:"17-264-01");

  script_name(english:"Schneider Electric InduSoft Web Studio < 8.0 SP2 Patch 1 Unspecified Remote Command Execution (LFSEC00000121)");
  script_summary(english:"Checks the version of InduSoft Web Studio.");

  script_set_attribute(attribute:"synopsis", value:
"The InduSoft Web Studio software running on the remote host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Schneider Electric
InduSoft Web Studio software running on the remote host is prior to
8.0 SP2 Patch 1. It is, therefore, affected by an unspecified flaw
that allow a remote attacker to bypass authentication mechanisms and
execute arbitrary commands with elevated privileges.");
  # https://sw.aveva.com/hubfs/pdf/security-bulletin/LFSec00000121.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e526f661");
  # http://www.indusoft.com/Products-Downloads/Download-Library/Current-Release-Notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83305c3d");
  script_set_attribute(attribute:"see_also", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-264-01");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Schneider Electric InduSoft Web Studio 8.0 SP2 Patch 1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:schneider_electric:indusoft_web_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SCADA");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("scada_app_indusoft_web_studio_detect.nbin");
  script_require_keys("installed_sw/InduSoft Web Studio HTTP Server");

  exit(0);
}

include("vcf.inc");
include("http.inc");

app_name = "InduSoft Web Studio HTTP Server";
port = get_http_port(default:80);

app_info = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "0",  "fixed_version" : "8.0.2.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
