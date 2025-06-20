#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16136);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");
  script_bugtraq_id(12243);

  script_name(english:"GNU Mailman Multiple Unspecified Remote Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running GNU Mailman, a web-based application
for managing mailing lists.  The version running on the remote
host has multiple flaws, such as information disclosure and
cross-site scripting.  These vulnerabilities could allow a
remote attacker to gain unauthorized access.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:mailman");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2024 Tenable Network Security, Inc.");

  script_dependencies("mailman_password_retrieval.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
kb = get_kb_item("www/" + port + "/Mailman");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];
if ( ereg(pattern:"^([0-1]\.|2\.(0\.|1\.[0-5][^0-9]))", string:version) )
{
	security_hole ( port );
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

