#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/12/05. Deprecated as this plugin should not have been generated.
##

include('compat.inc');

if (description)
{
  script_id(186548);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/05");

  script_name(english:"WordPress (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated");
  script_set_attribute(attribute:"description", value:
"WordPress versions  are affected by one or more vulnerabilities");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/download/releases/");
  # https://wordpress.org/news/2023/12/alert-wordpress-security-team-impersonation-scams/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad821493");
  script_set_attribute(attribute:"solution", value:
"N/A");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

exit(0, 'This plugin has been deprecated as it should not have been generated.');
