#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2023-1705.
##

include('compat.inc');

if (description)
{
  script_id(173282);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2022-37797");

  script_name(english:"Amazon Linux AMI : lighttpd (ALAS-2023-1705)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of lighttpd installed on the remote host is prior to 1.4.53-1.37. It is, therefore, affected by a
vulnerability as referenced in the ALAS-2023-1705 advisory.

    In lighttpd 1.4.65, mod_wstunnel does not initialize a handler function pointer if an invalid HTTP request
    (websocket handshake) is received. It leads to null pointer dereference which crashes the server. It could
    be used by an external attacker to cause denial of service condition. (CVE-2022-37797)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2023-1705.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-37797.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update lighttpd' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37797");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_authn_gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_authn_mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_authn_pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_mysql_vhost");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'lighttpd-1.4.53-1.37.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-1.4.53-1.37.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-debuginfo-1.4.53-1.37.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-debuginfo-1.4.53-1.37.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-fastcgi-1.4.53-1.37.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-fastcgi-1.4.53-1.37.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-mod_authn_gssapi-1.4.53-1.37.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-mod_authn_gssapi-1.4.53-1.37.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-mod_authn_mysql-1.4.53-1.37.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-mod_authn_mysql-1.4.53-1.37.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-mod_authn_pam-1.4.53-1.37.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-mod_authn_pam-1.4.53-1.37.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-mod_geoip-1.4.53-1.37.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-mod_geoip-1.4.53-1.37.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-mod_mysql_vhost-1.4.53-1.37.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lighttpd-mod_mysql_vhost-1.4.53-1.37.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd / lighttpd-debuginfo / lighttpd-fastcgi / etc");
}
