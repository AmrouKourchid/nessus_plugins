#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com
#      Added BugtraqID

# References:
# Date:  Thu, 25 Oct 2001 12:21:37 -0700 (PDT)
# From: "MK Ultra" <mkultra@dqc.org>
# To: bugtraq@securityfocus.com
# Subject: Weak authentication in iBill's Password Management CGI

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11083);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id("CVE-2001-0839");
  script_bugtraq_id(3476);

  script_name(english:"iBill ibillpm.pl Password Generation Weakness");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a CGI application that is affected by
a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running iBill, an internet billing application.
Some versions of the 'ibillpm.pl' CGI use a weak password management
system that can be brute-forced.

** No flaw was tested. Your script might be a safe version.");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=bugtraq&m=100404371423927&w=2");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibill_internet_billing_company:processing_plus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2002-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

res = is_cgi_installed3(item:"ibillpm.pl", port:port);
if(res)security_hole(port);
# Note: we could try to access it. If we get a 403 the site is safe.
