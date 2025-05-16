#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASECS-2024-041.
##

include('compat.inc');

if (description)
{
  script_id(206636);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2023-39326",
    "CVE-2024-23650",
    "CVE-2024-23652",
    "CVE-2024-23653",
    "CVE-2024-24557"
  );
  script_xref(name:"IAVA", value:"2024-A-0071");
  script_xref(name:"IAVB", value:"2023-B-0096-S");

  script_name(english:"Amazon Linux 2 : docker (ALASECS-2024-041)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of docker installed on the remote host is prior to 25.0.3-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2ECS-2024-041 advisory.

    A malicious HTTP sender can use chunk extensions to cause a receiver reading from a request or response
    body to read many more bytes from the network than are in the body. A malicious HTTP client can further
    exploit this to cause a server to automatically read a large amount of data (up to about 1GiB) when a
    handler fails to read the entire body of a request. Chunk extensions are a little-used HTTP feature which
    permit including additional metadata in a request or response body sent using the chunked encoding. The
    net/http chunked encoding reader discards this metadata. A sender can exploit this by inserting a large
    metadata segment with each byte transferred. The chunk reader now produces an error if the ratio of real
    body to encoded bytes grows too small. (CVE-2023-39326)

    BuildKit is a toolkit for converting source code to build artifacts in an efficient, expressive and
    repeatable manner. A malicious BuildKit client or frontend could craft a request that could lead to
    BuildKit daemon crashing with a panic. The issue has been fixed in v0.12.5. As a workaround, avoid using
    BuildKit frontends from untrusted sources. (CVE-2024-23650)

    BuildKit is a toolkit for converting source code to build artifacts in an efficient, expressive and
    repeatable manner. A malicious BuildKit frontend or Dockerfile using RUN --mount could trick the feature
    that removes empty files created for the mountpoints into removing a file outside the container, from the
    host system. The issue has been fixed in v0.12.5. Workarounds include avoiding using BuildKit frontends
    from an untrusted source or building an untrusted Dockerfile containing RUN --mount feature.
    (CVE-2024-23652)

    BuildKit is a toolkit for converting source code to build artifacts in an efficient, expressive and
    repeatable manner. In addition to running containers as build steps, BuildKit also provides APIs for
    running interactive containers based on built images. It was possible to use these APIs to ask BuildKit to
    run a container with elevated privileges. Normally, running such containers is only allowed if special
    `security.insecure` entitlement is enabled both by buildkitd configuration and allowed by the user
    initializing the build request. The issue has been fixed in v0.12.5 . Avoid using BuildKit frontends from
    untrusted sources. (CVE-2024-23653)

    Moby is an open-source project created by Docker to enable software containerization. The classic builder
    cache system is prone to cache poisoning if the image is built FROM scratch. Also, changes to some
    instructions (most important being HEALTHCHECK and ONBUILD) would not cause a cache miss. An attacker with
    the knowledge of the Dockerfile someone is using could poison their cache by making them pull a specially
    crafted image that would be considered as a valid cache candidate for some build steps. 23.0+ users are
    only affected if they explicitly opted out of Buildkit (DOCKER_BUILDKIT=0 environment variable) or are
    using the /build API endpoint. All users on versions older than 23.0 could be impacted. Image build API
    endpoint (/build) and ImageBuild function from github.com/docker/docker/client is also affected as it the
    uses classic builder by default. Patches are included in 24.0.9 and 25.0.2 releases. (CVE-2024-24557)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASECS-2024-041.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-39326.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-23650.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-23652.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-23653.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-24557.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update docker' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-ecs"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'docker-25.0.3-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'docker-25.0.3-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'docker-debuginfo-25.0.3-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'docker-debuginfo-25.0.3-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-debuginfo");
}
