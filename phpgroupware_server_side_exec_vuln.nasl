#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14295);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id("CVE-2004-0016");
  script_bugtraq_id(9387);

  script_name(english:"phpGroupWare Calendar Module Holiday File Save Extension Feature Arbitrary File Execution");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host.");
  script_set_attribute(attribute:"description", value:
"It has been reported that the version of phpGroupWare hosted on the
remote web server may be affected by a vulnerability that allows
remote attackers to upload scripts and then execute them on the
affected system.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpgroupware.org/");
  script_set_attribute(attribute:"solution", value:
"Update to version 0.9.14.007 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpgroupware:phpgroupware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2024 Tenable Network Security, Inc.");

  script_dependencies("phpgroupware_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80, embedded:TRUE);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if (! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);

if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-3]\.|14\.0*[0-6]([^0-9]|$)))", string:matches[1]) )
	security_hole(port);
