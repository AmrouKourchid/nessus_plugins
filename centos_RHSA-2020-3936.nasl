##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3936 and
# CentOS Errata and Security Advisory 2020:3936 respectively.
##

include('compat.inc');

if (description)
{
  script_id(141586);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

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
  script_bugtraq_id(105658, 107375, 108023);
  script_xref(name:"RHSA", value:"2020:3936");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"CentOS 7 : ipa (RHSA-2020:3936)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2020:3936 advisory.

  - jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks when a cross-domain Ajax request
    is performed without the dataType option, causing text/javascript responses to be executed.
    (CVE-2015-9251)

  - In Bootstrap 3.x before 3.4.0 and 4.x-beta before 4.0.0-beta.2, XSS is possible in the data-target
    attribute, a different vulnerability than CVE-2018-14041. (CVE-2016-10735)

  - In Bootstrap before 4.1.2, XSS is possible in the collapse data-parent attribute. (CVE-2018-14040)

  - In Bootstrap before 4.1.2, XSS is possible in the data-container property of tooltip. (CVE-2018-14042)

  - In Bootstrap before 3.4.0, XSS is possible in the tooltip data-viewport attribute. (CVE-2018-20676)

  - In Bootstrap before 3.4.0, XSS is possible in the affix configuration target property. (CVE-2018-20677)

  - jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true,
    {}, ...) because of Object.prototype pollution. If an unsanitized source object contained an enumerable
    __proto__ property, it could extend the native Object.prototype. (CVE-2019-11358)

  - In Bootstrap before 3.4.1 and 4.3.x before 4.3.1, XSS is possible in the tooltip or popover data-template
    attribute. (CVE-2019-8331)

  - In jQuery versions greater than or equal to 1.2 and before 3.5.0, passing HTML from untrusted sources -
    even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and
    others) may execute untrusted code. This problem is patched in jQuery 3.5.0. (CVE-2020-11022)

  - A flaw was found in all ipa versions 4.x.x through 4.8.0. When sending a very long password (>= 1,000,000
    characters) to the server, the password hashing process could exhaust memory and CPU leading to a denial
    of service and the website becoming unresponsive. The highest threat from this vulnerability is to system
    availability. (CVE-2020-1722)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3936");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11022");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'ipa-client-4.6.8-5.el7.centos', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-4.6.8-5.el7.centos', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-common-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-common-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-common-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-common-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-python-compat-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-python-compat-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.6.8-5.el7.centos.centos', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.6.8-5.el7.centos.centos', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-common-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-common-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-dns-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-dns-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.6.8-5.el7.centos.centos', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.6.8-5.el7.centos.centos', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipaclient-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipaclient-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipalib-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipalib-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipaserver-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipaserver-4.6.8-5.el7.centos.centos.centos.centos.centos.centos.centos.centos', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ipa-client / ipa-client-common / ipa-common / etc');
}
