#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85300);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id(
    "CVE-2015-6831",
    "CVE-2015-6832",
    "CVE-2015-6833",
    "CVE-2015-8867",
    "CVE-2015-8874",
    "CVE-2015-8879"
  );
  script_bugtraq_id(
    76735,
    76737,
    76739,
    87481,
    90714,
    90842
  );

  script_name(english:"PHP 5.6.x < 5.6.12 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.6.x prior to 5.6.12. It is, therefore, affected by
multiple vulnerabilities :

  - A use-after-free error exists in file spl_dllist.c due
    to improper sanitization of input to the unserialize()
    function. An attacker can exploit this, by using a
    specially crafted SplDoublyLinkedList object, to
    deference freed memory and thus execute arbitrary code.

  - A use-after-free error exists in file spl_observer.c due
    to improper sanitization of input to the unserialize()
    function. An attacker can exploit this, by using a 
    specially crafted SplObjectStorage object, to deference
    freed memory and thus execute arbitrary code.

  - A use-after-free error exists in file spl_array.c due
    to improper sanitization of input to the unserialize()
    function. An attacker can exploit this, by using a
    specially crafted SplArrayObject object, to deference
    freed memory and thus execute arbitrary code.

  - A flaw exists in file zend_exceptions.c due to the
    improper use of the function unserialize() during
    recursive method calls. A remote attacker can exploit
    this to crash an application using PHP.

  - A flaw exists in file zend_exceptions.c due to
    insufficient type checking by functions unserialize()
    and __toString(). A remote attacker can exploit this to
    cause a NULL pointer deference or unexpected method
    execution, thus causing an application using PHP to
    crash.

  - A path traversal flaw exists in file phar_object.c due
    to improper sanitization of user-supplied input. An
    attacker can exploit this to write arbitrary files.

  - Multiple type confusion flaws exist in the _call()
    method in file php_http.c when handling calls for
    zend_hash_get_current_key or 'Z*'. An attacker can
    exploit this to disclose memory contents or crash
    an application using PHP.

  - A dangling pointer error exists in file spl_array.c due
    to improper sanitization of input to the unserialize()
    function. An attacker can exploit this, by using a
    specially crafted SplDoublyLinkedList object, to gain
    control over a deallocated pointer and thus execute
    arbitrary code.

  - A flaw exists in the file gd.c due to the improper
    handling of images with large negative coordinates by
    the imagefilltoborder() function. An attacker can
    exploit this to cause a stack overflow, thus crashing
    an application using PHP.

  - A flaw exists in the file php_odbc.c when the
    odbc_fetch_array() function handles columns that are
    defined as NVARCHAR(MAX). An attacker can exploit this
    to crash an application using PHP.

  - The openssl_random_pseudo_bytes() function in file
    openssl.c does not generate sufficiently random numbers.
    This allows an attacker to more easily predict the
    results, thus allowing further attacks to be carried
    out.

  - A user-after-free error exists in the unserialize()
    function in spl_observer.c due to improper validation
    of user-supplied input. A remote attacker can exploit
    this to dereference already freed memory, potentially
    resulting in the execution of arbitrary code.

  - A type confusion flaw exists in the
    serialize_function_call() function in soap.c due to
    improper validation of input passed via the header
    field. A remote attacker can exploit this to execute
    arbitrary code.

  - A use-after-free error exists in the unserialize()
    function in spl_dllist.c that is triggered during the
    deserialization of user-supplied input. A remote
    attacker can exploit this to dereference already freed
    memory, potentially resulting in the execution of
    arbitrary code.

  - A user-after-free error exists in the gmp_unserialize()
    function in gmp.c due to improper validation of
    user-supplied input. A remote attacker can exploit this
    to dereference already freed memory, potentially
    resulting in the execution of arbitrary code.

  - An integer truncation flaw exists in the
    zend_hash_compare() function in zend_hash.c that is
    triggered when comparing arrays. A remote attacker can
    exploit this to cause arrays to be improperly matched
    during comparison.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.12");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2015/Aug/17");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2015/Aug/18");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2015/Aug/19");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=69793");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=70121");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.6.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6831");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

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

if (version =~ "^5\.6\.([0-9]|1[01])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version +
      '\n  Fixed version     : 5.6.12' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
