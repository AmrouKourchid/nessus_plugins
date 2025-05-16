#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1683.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151275);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2019-25032",
    "CVE-2019-25033",
    "CVE-2019-25034",
    "CVE-2019-25035",
    "CVE-2019-25036",
    "CVE-2019-25037",
    "CVE-2019-25038",
    "CVE-2019-25039",
    "CVE-2019-25040",
    "CVE-2019-25041",
    "CVE-2019-25042",
    "CVE-2020-28935"
  );
  script_xref(name:"ALAS", value:"2021-1683");

  script_name(english:"Amazon Linux 2 : unbound (ALAS-2021-1683)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of unbound installed on the remote host is prior to 1.7.3-15. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1683 advisory.

    2024-01-19: CVE-2019-25033 was added to this advisory.

    A flaw was found in unbound. An integer overflow in regional_alloc function may lead to a buffer overflow
    of the allocated buffer if the size can be controlled by an attacker and can be big enough. The highest
    threat from this vulnerability is to data confidentiality and integrity as well as service availability.
    (CVE-2019-25032)

    Unbound before 1.9.5 allows an integer overflow in the regional allocator via the ALIGN_UP macro. NOTE:
    The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound
    installation cannot be remotely or locally exploited. (CVE-2019-25033)

    A flaw was found in unbound. An integer overflow in the sldns_str2wire_dname_buf_origin function may lead
    to a buffer overflow. The highest threat from this vulnerability is to data confidentiality and integrity
    as well as service availability. (CVE-2019-25034)

    A flaw was found in unbound. An out-of-bounds write in the sldns_bget_token_par function may be abused by
    a remote attacker. The highest threat from this vulnerability is to data confidentiality and integrity as
    well as service availability. (CVE-2019-25035)

    A flaw was found in unbound. A reachable assertion in the synth_cname function can be triggered by sending
    invalid packets to the server. If asserts are disabled during compilation, this issue might lead to an
    out-of-bounds write in dname_pkt_copy function. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as service availability. (CVE-2019-25036)

    A flaw was found in unbound. A reachable assertion in the dname_pkt_copy function can be triggered by
    sending invalid packets to the server. The highest threat from this vulnerability is to service
    availability. (CVE-2019-25037)

    A flaw was found in unbound. An integer overflow in dnsc_load_local_data function may lead to a buffer
    overflow of the allocated buffer if the size can be controlled by an attacker. The highest threat from
    this vulnerability is to data confidentiality and integrity as well as service availability.
    (CVE-2019-25038)

    A flaw was found in unbound. An integer overflow in ub_packed_rrset_key function may lead to a buffer
    overflow of the allocated buffer if the size can be controlled by an attacker. The highest threat from
    this vulnerability is to data confidentiality and integrity as well as service availability.
    (CVE-2019-25039)

    A flaw was found in unbound. An infinite loop in dname_pkt_copy function could be triggered by a remote
    attacker. The highest threat from this vulnerability is to service availability. (CVE-2019-25040)

    A flaw was found in unbound. A reachable assertion in the dname_pkt_copy function can be triggered through
    compressed names. The highest threat from this vulnerability is to service availability. (CVE-2019-25041)

    A flaw was found in unbound. An out-of-bounds write in the rdata_copy function may be abused by a remote
    attacker. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    service availability. (CVE-2019-25042)

    A symbolic link traversal vulnerability was found in unbound in the way it writes its PID file while
    starting up. This flaw allows a local attacker with access to the unbound user to set up a link to another
    file, owned by root, and make unbound overwrite it during its next restart, destroying the original
    content. The highest threat from this vulnerability is integrity. (CVE-2020-28935)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1683.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-25032.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-25033.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-25034.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-25035.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-25036.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-25037.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-25038.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-25039.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-25040.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-25041.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-25042.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28935.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update unbound' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-25042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python2-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:unbound-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:unbound-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:unbound-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var pkgs = [
    {'reference':'python2-unbound-1.7.3-15.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-unbound-1.7.3-15.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-unbound-1.7.3-15.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-unbound-1.7.3-15.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-unbound-1.7.3-15.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-unbound-1.7.3-15.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-1.7.3-15.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-1.7.3-15.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-1.7.3-15.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-debuginfo-1.7.3-15.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-debuginfo-1.7.3-15.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-debuginfo-1.7.3-15.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-devel-1.7.3-15.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-devel-1.7.3-15.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-devel-1.7.3-15.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-libs-1.7.3-15.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-libs-1.7.3-15.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-libs-1.7.3-15.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2-unbound / python3-unbound / unbound / etc");
}
