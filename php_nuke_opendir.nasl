#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10655);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id("CVE-2001-0321");

  script_name(english:"PHP-Nuke opendir.php Traversal Arbitrary File Read");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote server.");
  script_set_attribute(attribute:"description", value:
"The remote host has the CGI 'opendir.php' installed. This CGI allows
anyone to read arbitrary files with the privileges of the HTTP server.");
  script_set_attribute(attribute:"solution", value:
"Upgrade your version of phpnuke.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/04/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpnuke:php-nuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2001-2024 Tenable Network Security, Inc.");

  script_dependencies("php_nuke_installed.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
installed = get_kb_item("www/" + port + "/php-nuke");
if ( ! installed ) exit(0);
array = eregmatch(pattern:"(.*) under (.*)", string:installed);
if ( ! array ) exit(0);
url = array[2];


r = http_send_recv3(method:"GET",item:string(url, "/opendir.php?/etc/passwd"), port:port);
if (isnull(r)) exit(0);
res = strcat(r[0], r[1], '\r\n', r[2]);
if(egrep(pattern:".*root:.*:0:[01]:.*", string:res))
  security_warning(port);

