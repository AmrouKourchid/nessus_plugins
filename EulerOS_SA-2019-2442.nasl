#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131596);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/08");

  script_cve_id(
    "CVE-2018-20852",
    "CVE-2019-16056",
    "CVE-2019-16935",
    "CVE-2019-17514",
    "CVE-2019-9740"
  );
  script_xref(name:"IAVA", value:"2020-A-0340-S");

  script_name(english:"EulerOS 2.0 SP2 : python (EulerOS-SA-2019-2442)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - library/glob.html in the Python 2 and 3 documentation
    before 2016 has potentially misleading information
    about whether sorting occurs, as demonstrated by
    irreproducible cancer-research results. NOTE: the
    effects of this documentation cross application
    domains, and thus it is likely that security-relevant
    code elsewhere is affected. This issue is not a Python
    implementation bug, and there are no reports that NMR
    researchers were specifically relying on
    library/glob.html. In other words, because the older
    documentation stated 'finds all the pathnames matching
    a specified pattern according to the rules used by the
    Unix shell,' one might have incorrectly inferred that
    the sorting that occurs in a Unix shell also occurred
    for glob.glob. There is a workaround in newer versions
    of Willoughby nmr-data_compilation-p2.py and
    nmr-data_compilation-p3.py, which call sort()
    directly.(CVE-2019-17514)

  - The documentation XML-RPC server in Python through
    2.7.16, 3.x through 3.6.9, and 3.7.x through 3.7.4 has
    XSS via the server_title field. This occurs in
    Lib/DocXMLRPCServer.py in Python 2.x, and in
    Lib/xmlrpc/server.py in Python 3.x. If set_server_title
    is called with untrusted input, arbitrary JavaScript
    can be delivered to clients that visit the http URL for
    this server.(CVE-2019-16935)

  - An issue was discovered in urllib2 in Python 2.x
    through 2.7.16 and urllib in Python 3.x through 3.7.3.
    CRLF injection is possible if the attacker controls a
    url parameter, as demonstrated by the first argument to
    urllib.request.urlopen with \r\n (specifically in the
    query string after a ? character) followed by an HTTP
    header or a Redis command.(CVE-2019-9740)

  - An issue was discovered in Python through 2.7.16, 3.x
    through 3.5.7, 3.6.x through 3.6.9, and 3.7.x through
    3.7.4. The email module wrongly parses email addresses
    that contain multiple @ characters. An application that
    uses the email module and implements some kind of
    checks on the From/To headers of a message could be
    tricked into accepting an email address that should be
    denied. An attack may be the same as in CVE-2019-11340
    however, this CVE applies to Python more
    generally.(CVE-2019-16056)

  - http.cookiejar.DefaultPolicy.domain_return_ok in
    Lib/http/cookiejar.py in Python before 3.7.3 does not
    correctly validate the domain: it can be tricked into
    sending existing cookies to the wrong server. An
    attacker may abuse this flaw by using a server with a
    hostname that has another valid hostname as a suffix
    (e.g., pythonicexample.com to steal cookies for
    example.com). When a program uses
    http.cookiejar.DefaultPolicy and tries to do an HTTP
    connection to an attacker-controlled server, existing
    cookies can be leaked to the attacker. This affects 2.x
    through 2.7.16, 3.x before 3.4.10, 3.5.x before 3.5.7,
    3.6.x before 3.6.9, and 3.7.x before
    3.7.3.(CVE-2018-20852)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2442
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a89cbebd");
  script_set_attribute(attribute:"solution", value:
"Update the affected python packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17514");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["python-2.7.5-58.h20",
        "python-devel-2.7.5-58.h20",
        "python-libs-2.7.5-58.h20",
        "tkinter-2.7.5-58.h20"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
