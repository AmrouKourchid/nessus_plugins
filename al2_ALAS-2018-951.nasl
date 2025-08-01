#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-951.
#

include('compat.inc');

if (description)
{
  script_id(109122);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/31");

  script_cve_id("CVE-2018-1000005", "CVE-2018-1000007");
  script_xref(name:"ALAS", value:"2018-951");

  script_name(english:"Amazon Linux 2 : curl (ALAS-2018-951)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"HTTP authentication leak in redirects

libcurl might accidentally leak authentication data to third parties.
When asked to send custom headers in its HTTP requests, libcurl will
send that set of headers first to the host in the initial URL but
also, if asked to follow redirects and a 30X HTTP response code is
returned, to the host mentioned in URL in the `Location:` response
header value. Sending the same set of headers to subsequest hosts is
in particular a problem for applications that pass on custom
`Authorization:` headers, as this header often contains privacy
sensitive information or data that could allow others to impersonate
the libcurl-using client's request. (CVE-2018-1000007)

Out-of-bounds read in code handling HTTP/2 trailers

libcurl contains an out bounds read in code handling HTTP/2 trailers.
It was reported (https://github.com/curl/curl/pull/2231) that reading
an HTTP/2 trailer could mess up future trailers since the stored size
was one byte less than required. The problem is that the code that
creates HTTP/1-like headers from the HTTP/2 trailer data once appended
a string like `:` to the target buffer, while this was recently
changed to `: ` (a space was added after the colon) but the following
math wasn't updated correspondingly. When accessed, the data is read
out of bounds and causes either a crash or that the (too large) data
gets passed to client write. This could lead to a denial-of-service
situation or an information disclosure if someone has a service that
echoes back or uses the trailers for something. (CVE-2018-1000005)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2018-951.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update curl' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000005");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-1000007");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"curl-7.55.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"curl-debuginfo-7.55.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libcurl-7.55.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libcurl-devel-7.55.1-9.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / libcurl / libcurl-devel");
}
