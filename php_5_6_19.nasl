#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90008);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id("CVE-2016-3141", "CVE-2016-3142");
  script_bugtraq_id(
    84271,
    84306,
    84307,
    84348,
    84349,
    84350,
    84351
  );

  script_name(english:"PHP 5.6.x < 5.6.19 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.6.x prior to 5.6.19. It is, therefore, affected by
multiple vulnerabilities :

  - A use-after-free error exists in file ext/wddx/wddx.c in
    the php_wddx_pop_element() function when handling XML
    data. An unauthenticated, remote attacker can exploit
    this, via crafted XML data, to dereference already freed
    memory, resulting in the execution of arbitrary code.
    (CVE-2016-3141)

  - An out-of-bounds read error exists in file
    ext/phar/zip.c in the phar_parse_zipfile() function that
    allows an unauthenticated, remote attacker to cause a
    denial of service or to gain access to sensitive
    information. (CVE-2016-3142)

  - A NULL pointer dereference flaw exists in file
    ext/xsl/xsltprocessor.c in the xsl_ext_function_php()
    function that allows an unauthenticated, remote attacker
    to cause a denial of service.

  - A flaw exists in file sapi/cli/php_cli_server.c due to
    the built-in HTTP server not properly restricting file
    requests. An unauthenticated, remote attacker can
    exploit this to access arbitrary files.

  - A use-after-free error exists in Zend Opcache when
    updating cached directory names that have been cached in
    the current working directory. An unauthenticated,
    remote attacker can exploit this to deference already
    freed memory, resulting in the execution of arbitrary
    code.

  - A NULL pointer dereference flaw exists in file
    ext/zip/php_zip.c in the Zip::ExtractTo() method that
    allows an unauthenticated, remote attacker to cause
    a denial of service.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.19");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.6.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3141");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (version !~ "^5\.6\.([0-9]|1[0-8])($|[^0-9])")
  audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

security_report_v4(
  port  : port,
  extra :
    '\n  Version source    : '+source +
    '\n  Installed version : '+version +
    '\n  Fixed version     : 5.6.19' +
    '\n',
  severity:SECURITY_HOLE
);
