#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-193.
##

include('compat.inc');

if (description)
{
  script_id(166999);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2021-33196",
    "CVE-2021-38297",
    "CVE-2021-41771",
    "CVE-2021-41772",
    "CVE-2021-44716",
    "CVE-2021-44717",
    "CVE-2022-1705",
    "CVE-2022-1962",
    "CVE-2022-1996",
    "CVE-2022-24675",
    "CVE-2022-27191",
    "CVE-2022-27664",
    "CVE-2022-28131",
    "CVE-2022-28327",
    "CVE-2022-29526",
    "CVE-2022-30629",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-30635",
    "CVE-2022-32148",
    "CVE-2022-32189",
    "CVE-2022-32190"
  );
  script_xref(name:"IAVB", value:"2022-B-0025-S");

  script_name(english:"Amazon Linux 2022 : golang, golang-bin, golang-misc (ALAS2022-2022-193)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2022-2022-193 advisory.

    A flaw was found in golang. The HTTP/1 client accepted invalid Transfer-Encoding headers indicating
    chunked encoding. This issue could allow request smuggling, but only if combined with an intermediate
    server that also improperly accepts the header as invalid. (CVE-2022-1705)

    A flaw was found in the golang standard library, go/parser. When calling any Parse functions on the Go
    source code, which contains deeply nested types or declarations, a panic can occur due to stack
    exhaustion. This issue allows an attacker to impact system availability. (CVE-2022-1962)

    In net/http in Go before 1.18.6 and 1.19.x before 1.19.1, attackers can cause a denial of service because
    an HTTP/2 connection can hang during closing if shutdown were preempted by a fatal error. (CVE-2022-27664)

    A flaw was found in golang encoding/xml. When calling Decoder.Skip while parsing a deeply nested XML
    document, a panic can occur due to stack exhaustion and allows an attacker to impact system availability.
    (CVE-2022-28131)

    A flaw was found in the golang standard library, io/fs. Calling Glob on a path that contains a large
    number of path separators can cause a panic issue due to stack exhaustion. This could allow an attacker to
    impact availability. (CVE-2022-30630)

    A flaw was found in golang. Calling the Reader.Read method on an archive that contains a large number of
    concatenated 0-length compressed files can cause a panic issue due to stack exhaustion. (CVE-2022-30631)

    A flaw was found in golang. Calling Glob on a path that contains a large number of path separators can
    cause a panic issue due to stack exhaustion. This can cause an attacker to impact availability.
    (CVE-2022-30632)

    Uncontrolled recursion in Unmarshal in encoding/xml before Go 1.17.12 and Go 1.18.4 allows an attacker to
    cause a panic due to stack exhaustion via unmarshalling an XML document into a Go struct which has a
    nested field that uses the any field tag. (CVE-2022-30633)

    A flaw was found in golang. When calling Decoder.Decode on a message that contains deeply nested
    structures, a panic can occur due to stack exhaustion and allows an attacker to impact system
    availability. (CVE-2022-30635)

    Improper exposure of client IP addresses in net/http before Go 1.17.12 and Go 1.18.4 can be triggered by
    calling httputil.ReverseProxy.ServeHTTP with a Request.Header map containing a nil value for the
    X-Forwarded-For header, which causes ReverseProxy to set the client IP as the value of the X-Forwarded-For
    header. (CVE-2022-32148)

    JoinPath and URL.JoinPath do not remove ../ path elements appended to a relative path. For example,
    JoinPath(https://go.dev, ../go) returns the URL https://go.dev/../go, despite the JoinPath
    documentation stating that ../ path elements are removed from the result. (CVE-2022-32190)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-193.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-33196.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-38297.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-41771.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-41772.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44716.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44717.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1705.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1962.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1996.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-24675.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27191.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27664.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-28131.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-28327.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-29526.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30629.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30630.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30631.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30632.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30633.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30635.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32148.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32189.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32190.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update golang --releasever=2022.0.20221102' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38297");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'golang-1.19.1-1.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.19.1-1.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.19.1-1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.19.1-1.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.19.1-1.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.19.1-1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-docs-1.19.1-1.amzn2022.0.2', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-misc-1.19.1-1.amzn2022.0.2', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-race-1.19.1-1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-shared-1.19.1-1.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-shared-1.19.1-1.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-shared-1.19.1-1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-src-1.19.1-1.amzn2022.0.2', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-tests-1.19.1-1.amzn2022.0.2', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "golang / golang-bin / golang-docs / etc");
}
