#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77403);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id(
    "CVE-2014-2497",
    "CVE-2014-3538",
    "CVE-2014-3587",
    "CVE-2014-3597",
    "CVE-2014-5120"
  );
  script_bugtraq_id(
    66233,
    66406,
    68348,
    69322,
    69325,
    69375
  );

  script_name(english:"PHP 5.5.x < 5.5.16 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server is running a version of
PHP 5.5.x prior to 5.5.16. It is, therefore, affected by the following
vulnerabilities :

  - LibGD contains a NULL pointer dereference flaw in its
    'gdImageCreateFromXpm' function in the 'gdxpm.c' file.
    By using a specially crafted color mapping, a remote
    attacker could cause a denial of service.
    (CVE-2014-2497)

  - The original upstream patch for CVE-2013-7345 did not
    provide a complete solution. It is, therefore, still
    possible for a remote attacker to deploy a specially
    crafted input file to cause excessive resources to be
    used when trying to detect the file type using awk
    regular expression rules. This can cause a denial of
    service. (CVE-2014-3538)

  - An integer overflow flaw exists in the 'cdf.c' file. By
    using a specially crafted CDF file, a remote attacker
    could cause a denial of service. (CVE-2014-3587)

  - There are multiple buffer overflow flaws in the 'dns.c'
    file related to the 'dns_get_record' and 'dn_expand'
    functions. By using a specially crafted DNS record,
    a remote attacker could exploit these to cause a denial
    of service or execute arbitrary code. (CVE-2014-3597)

  - There exist multiple flaws in the GD component within
    the 'gd_ctx.c' file where user-supplied input is not
    properly validated to ensure that pathnames lack %00
    sequences. By using specially crafted input, a remote
    attacker could overwrite arbitrary files.
    (CVE-2014-5120)

Note that Nessus has not attempted to exploit these issues, but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.5.16");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67730");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67705");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67717");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=66901");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67716");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.5.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3597");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");

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
php = get_php_from_kb(port:port, exit_on_fail:TRUE);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.5)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.5\.") audit(AUDIT_NOT_DETECT, "PHP version 5.5.x", port);

if (version =~ "^5\.5\.([0-9]|1[0-5])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.5.16' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
