#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81081);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id(
    "CVE-2014-9425",
    "CVE-2014-9427",
    "CVE-2014-9652",
    "CVE-2014-9709",
    "CVE-2015-0231",
    "CVE-2015-0232"
  );
  script_bugtraq_id(
    71800,
    71833,
    72505,
    72539,
    72541,
    73306
  );

  script_name(english:"PHP 5.5.x < 5.5.21 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.5.x installed on the
remote host is prior to 5.5.21. It is, therefore, affected by multiple
vulnerabilities:

  - A double free vulnerability in the
    zend_ts_hash_graceful_destroy function in
    zend_ts_hash.c in the Zend Engine could allow a remote
    attacker to cause a denial of service. (CVE-2014-9425)

  - An out-of-bounds read flaw in file 'cgi_main.c' exists
    when nmap is used to process an invalid file that begins
    with a hash character (#) but lacks a newline character.
    A remote attacker, using a specially crafted PHP file,
    can exploit this vulnerability to disclose memory
    contents, cause a denial of service, or possibly execute
    code. (CVE-2014-9427)

  - The mconvert function in softmagic.c does not properly
    handle a certain string-length field during a copy of a
    truncated version of a Pascal string, which could allow
    a remote attacker to cause a denial of service.
    (CVE-2014-9652)

  - An out-of-bounds read issue exists in the GetCode_()
    function in 'gd_gif_in.c'. This allows a remote attacker
    to disclose memory contents. (CVE-2014-9709)

  - A use-after-free memory error exists in the
    process_nested_data() function in 'var_unserializer.re'
    due to improper handling of duplicate numerical keys
    within the serialized properties of an object. A remote
    attacker, using a crafted unserialize method call, can
    exploit this vulnerability to execute arbitrary code.
    (CVE-2015-0231)

  - A flaw exists in the exif_process_unicode() function in
    'exif.c' that allows freeing an uninitialized pointer. A
    remote attacker, using specially crafted EXIF data in a
    JPEG image, can exploit this to cause a denial of
    service or to execute arbitrary code. (CVE-2015-0232)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.5.21");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=68618");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=68710");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=68799");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.5.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0231");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/29");

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
if (version =~ "^5(\.5)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.5\.") audit(AUDIT_NOT_DETECT, "PHP version 5.5.x", port);

if (version =~ "^5\.5\.([0-9]|1[0-9]|20)($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version +
      '\n  Fixed version     : 5.5.21' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
