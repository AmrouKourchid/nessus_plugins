#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1324.
#

include('compat.inc');

if (description)
{
  script_id(131244);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/10");

  script_cve_id(
    "CVE-2019-10160",
    "CVE-2019-16056",
    "CVE-2019-9636",
    "CVE-2019-9740",
    "CVE-2019-9947",
    "CVE-2019-9948"
  );
  script_xref(name:"ALAS", value:"2019-1324");

  script_name(english:"Amazon Linux AMI : python34 (ALAS-2019-1324)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A security regression of CVE-2019-9636 was discovered in python, since
commit d537ab0ff9767ef024f26246899728f0116b1ec3, which still allows an
attacker to exploit CVE-2019-9636 by abusing the user and password
parts of a URL. When an application parses user-supplied URLs to store
cookies, authentication credentials, or other kind of information, it
is possible for an attacker to provide specially crafted URLs to make
the application locate host-related information (e.g. cookies,
authentication data) and send them to a different host than where it
should, unlike if the URLs had been correctly parsed. The result of an
attack may vary based on the application. (CVE-2019-10160)

An issue was discovered in urllib2 in Python 2.x through 2.7.16 and
urllib in Python 3.x through 3.7.3. CRLF injection is possible if the
attacker controls a url parameter, as demonstrated by the first
argument to urllib.request.urlopen with \r\n (specifically in the
query string after a ? character) followed by an HTTP header or a
Redis command. (CVE-2019-9740)

urllib in Python 2.x through 2.7.16 supports the local_file: scheme,
which makes it easier for remote attackers to bypass protection
mechanisms that blacklist file: URIs, as demonstrated by triggering a
urllib.urlopen('local_file:///etc/passwd') call. (CVE-2019-9948)

An issue was discovered in urllib2 in Python 2.x through 2.7.16 and
urllib in Python 3.x through 3.7.3. CRLF injection is possible if the
attacker controls a url parameter, as demonstrated by the first
argument to urllib.request.urlopen with \r\n (specifically in the path
component of a URL that lacks a ? character) followed by an HTTP
header or a Redis command. This is similar to the CVE-2019-9740 query
string issue. (CVE-2019-9947)

An issue was discovered in Python through 2.7.16, 3.x through 3.5.7,
3.6.x through 3.6.9, and 3.7.x through 3.7.4. The email module wrongly
parses email addresses that contain multiple @ characters. An
application that uses the email module and implements some kind of
checks on the From/To headers of a message could be tricked into
accepting an email address that should be denied. An attack may be the
same as in CVE-2019-11340 ; however, this CVE applies to Python more
generally. (CVE-2019-16056)

Python 2.7.x through 2.7.16 and 3.x through 3.7.2 is affected by:
Improper Handling of Unicode Encoding (with an incorrect netloc)
during NFKC normalization. The impact is: Information disclosure
(credentials, cookies, etc. that are cached against a given hostname).
The components are: urllib.parse.urlsplit, urllib.parse.urlparse. The
attack vector is: A specially crafted URL could be incorrectly parsed
to locate cookies or authentication data and send that information to
a different host than when parsed correctly. (CVE-2019-9636)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2019-1324.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update python34' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9948");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-9636");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"python34-3.4.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-debuginfo-3.4.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-devel-3.4.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-libs-3.4.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-test-3.4.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-tools-3.4.10-1.49.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python34 / python34-debuginfo / python34-devel / python34-libs / etc");
}
