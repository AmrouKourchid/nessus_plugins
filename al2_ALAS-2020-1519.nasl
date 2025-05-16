##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1519.
##

include('compat.inc');

if (description)
{
  script_id(141974);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/17");

  script_cve_id(
    "CVE-2015-9251",
    "CVE-2016-10735",
    "CVE-2018-14040",
    "CVE-2018-14042",
    "CVE-2018-20676",
    "CVE-2018-20677",
    "CVE-2019-8331",
    "CVE-2019-11358",
    "CVE-2020-1722",
    "CVE-2020-11022"
  );
  script_bugtraq_id(
    105658,
    107375,
    108023,
    108961
  );
  script_xref(name:"ALAS", value:"2020-1519");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Amazon Linux 2 : ipa (ALAS-2020-1519)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2-2020-1519 advisory.

    jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks when a cross-domain Ajax request
    is performed without the dataType option, causing text/javascript responses to be executed.
    (CVE-2015-9251)

    In Bootstrap 3.x before 3.4.0 and 4.x-beta before 4.0.0-beta.2, XSS is possible in the data-target
    attribute, a different vulnerability thanCVE-2018-14041. (CVE-2016-10735)

    In Bootstrap before 4.1.2, XSS is possible in the collapse data-parent attribute. (CVE-2018-14040)

    In Bootstrap before 4.1.2, XSS is possible in the data-container property of tooltip. (CVE-2018-14042)

    In Bootstrap before 3.4.0, XSS is possible in the tooltip data-viewport attribute. (CVE-2018-20676)

    In Bootstrap before 3.4.0, XSS is possible in the affix configuration target property. (CVE-2018-20677)

    A Prototype Pollution vulnerability was found in jquery. Untrusted JSON passed to the `extend` function
    could lead to modifying objects up the prototype chain, including the global Object. A crafted JSON object
    passed to a vulnerable method could lead to denial of service or data injection, with various
    consequences. (CVE-2019-11358)

    A cross-site scripting vulnerability was discovered in bootstrap. If an attacker could control the data
    given to tooltip or popover, they could inject HTML or Javascript into the rendered page when tooltip or
    popover events fired. (CVE-2019-8331)

    A Cross-site scripting (XSS) vulnerability exists in JQuery. This flaw allows an attacker with the ability
    to supply input to the 'HTML' function to inject Javascript into the page where that input is rendered,
    and have it delivered by the browser. (CVE-2020-11022)

    A flaw was found in IPA. When sending a very long password (>= 1,000,000 characters) to the server, the
    password hashing process could exhaust memory and CPU leading to a denial of service and the website
    becoming unresponsive. The highest threat from this vulnerability is to system availability.
    (CVE-2020-1722)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1519.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2015-9251");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2016-10735");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-14040");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-14042");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-20676");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-20677");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8331");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11358");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1722");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11022");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ipa' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11022");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'ipa-client-4.6.8-5.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-4.6.8-5.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-4.6.8-5.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-common-4.6.8-5.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-common-4.6.8-5.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-debuginfo-4.6.8-5.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-debuginfo-4.6.8-5.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-debuginfo-4.6.8-5.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-python-compat-4.6.8-5.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.6.8-5.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.6.8-5.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.6.8-5.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-common-4.6.8-5.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-dns-4.6.8-5.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.6.8-5.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.6.8-5.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.6.8-5.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipaclient-4.6.8-5.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipalib-4.6.8-5.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipaserver-4.6.8-5.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-client / ipa-client-common / ipa-common / etc");
}
