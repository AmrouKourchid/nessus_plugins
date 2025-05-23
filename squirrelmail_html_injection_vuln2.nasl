#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15718);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id("CVE-2004-1036");
  script_bugtraq_id(11653);

  script_name(english:"SquirrelMail decodeHeader Arbitrary HTML Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to an information disclosure attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running SquirrelMail, a webmail system written in PHP.

Versions of SquirrelMail prior to 1.4.4 are affected by an email HTML
injection issue.  A remote attacker can exploit this flaw to gain
access to the users' accounts.");
  script_set_attribute(attribute:"see_also", value:"http://article.gmane.org/gmane.mail.squirrelmail.user/21169");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Nov/133");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squirrelmail:squirrelmail");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2024 Tenable Network Security, Inc.");

  script_dependencies("squirrelmail_detect.nasl");
  script_require_keys("www/squirrelmail");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

host = get_host_name();
port = get_http_port(default:80);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/squirrelmail"));
if (isnull(installs))
	exit(0);

foreach install (installs)
{
	matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  	if (!isnull(matches))
	{
    		ver = matches[1];
    		dir = matches[2];

    		if (ereg(pattern:"^(0\..*|1\.([0-3]\..*|4\.[0-3][^0-9]))$", string:ver))
		{
      			security_warning(port);
      			exit(0);
    		}
  	}
}
