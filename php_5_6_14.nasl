#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86301);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id("CVE-2015-7803", "CVE-2015-7804");
  script_bugtraq_id(76959);

  script_name(english:"PHP 5.6.x < 5.6.14 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.6.x prior to 5.6.14. It is, therefore, affected by
multiple vulnerabilities :

  - A NULL pointer dereference flaw exists in the
    phar_get_fp_offset() function in ext/phar/util.c that is
    triggered when pointing to a non-existent file. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2015-7803)

  - An uninitialized pointer flaw exists in the
    phar_make_dirstream() function in ext/phar/dirstream.c
    that is triggered when handling a zip entry filename
    that is a single forward slash. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or to disclose sensitive information.
    (CVE-2015-7804)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.14");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.6.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.6\.") audit(AUDIT_NOT_DETECT, "PHP version 5.6.x", port);

if (version =~ "^5\.6\.([0-9]|1[0-3])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version +
      '\n  Fixed version     : 5.6.14' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
