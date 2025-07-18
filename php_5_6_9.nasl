#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83519);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id(
    "CVE-2006-7243",
    "CVE-2015-2325",
    "CVE-2015-2326",
    "CVE-2015-4021",
    "CVE-2015-4022",
    "CVE-2015-4024",
    "CVE-2015-4025",
    "CVE-2015-4026"
  );
  script_bugtraq_id(
    44951,
    74700,
    74902,
    74903,
    74904,
    75056,
    75174,
    75175
  );

  script_name(english:"PHP 5.6.x < 5.6.9 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.6.x running on the
remote web server is prior to 5.6.9. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple unspecified flaws in pcrelib.
    (CVE-2015-2325, CVE-2015-2326)

  - A flaw in the phar_parse_tarfile function in
    ext/phar/tar.c could allow a denial of service
    via a crafted entry in a tar archive.
    (CVE-2015-4021)

  - Multiple flaws exist related to using pathnames
    containing NULL bytes. A remote attacker can exploit
    these flaws, by combining the '\0' character with a safe
    file extension, to bypass access restrictions. This had
    been previously fixed but was reintroduced by a
    regression in versions 5.4+. (CVE-2006-7243,
    CVE-2015-4025)

  - An integer overflow condition exists in the
    ftp_genlist() function in ftp.c due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to cause a heap-based buffer overflow,
    resulting in a denial of service condition or possible
    remote code execution. (CVE-2015-4022)

  - A flaw exists in the multipart_buffer_headers() function
    in rfc1867.c due to improper handling of
    multipart/form-data in HTTP requests. A remote attacker
    can exploit this flaw to cause a consumption of CPU
    resources, resulting in a denial of service condition.
    (CVE-2015-4024)

  - A security bypass vulnerability exists due to a flaw in
    the pcntl_exec implementation that truncates a pathname
    upon encountering the '\x00' character. A remote
    attacker can exploit this, via a crafted first argument,
    to bypass intended extension restrictions and execute
    arbitrary files. (CVE-2015-4026)

  - A NULL pointer dereference flaw exists in the
    xsl_ext_function_php() function in xsltprocessor.c due
    to improper validation of user-supplied input. A remote
    attacker can exploit this to cause a denial of service
    condition.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.6.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4026");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/18");

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

if (version =~ "^5\.6\.[0-8]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version +
      '\n  Fixed version     : 5.6.9' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
