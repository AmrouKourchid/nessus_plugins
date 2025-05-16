#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2023:7055. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185649);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/14");

  script_cve_id(
    "CVE-2022-32885",
    "CVE-2023-27932",
    "CVE-2023-27954",
    "CVE-2023-28198",
    "CVE-2023-32370",
    "CVE-2023-32393",
    "CVE-2023-38133",
    "CVE-2023-38572",
    "CVE-2023-38592",
    "CVE-2023-38594",
    "CVE-2023-38595",
    "CVE-2023-38597",
    "CVE-2023-38599",
    "CVE-2023-38600",
    "CVE-2023-38611",
    "CVE-2023-39434",
    "CVE-2023-40397",
    "CVE-2023-40451"
  );
  script_xref(name:"RHSA", value:"2023:7055");

  script_name(english:"CentOS 8 : webkit2gtk3 (CESA-2023:7055)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2023:7055 advisory.

  - A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 15.6 and
    iPadOS 15.6, macOS Monterey 12.5, Safari 15.6. Processing maliciously crafted web content may lead to
    arbitrary code execution (CVE-2022-32885)

  - This issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.3, Safari
    16.4, iOS 16.4 and iPadOS 16.4, tvOS 16.4, watchOS 9.4. Processing maliciously crafted web content may
    bypass Same Origin Policy. (CVE-2023-27932)

  - The issue was addressed by removing origin information. This issue is fixed in macOS Ventura 13.3, Safari
    16.4, iOS 16.4 and iPadOS 16.4, iOS 15.7.4 and iPadOS 15.7.4, tvOS 16.4, watchOS 9.4. A website may be
    able to track sensitive user information. (CVE-2023-27954)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in iOS 16.4 and
    iPadOS 16.4, macOS Ventura 13.3. Processing web content may lead to arbitrary code execution.
    (CVE-2023-28198)

  - A logic issue was addressed with improved validation. This issue is fixed in macOS Ventura 13.3. Content
    Security Policy to block domains with wildcards may fail. (CVE-2023-32370)

  - The issue was addressed with improved memory handling. This issue is fixed in watchOS 9.3, tvOS 16.3,
    macOS Ventura 13.2, iOS 16.3 and iPadOS 16.3. Processing web content may lead to arbitrary code execution.
    (CVE-2023-32393)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.8 and iPadOS 15.7.8, iOS
    16.6 and iPadOS 16.6, tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may
    disclose sensitive information. (CVE-2023-38133)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.8 and iPadOS 15.7.8, iOS
    16.6 and iPadOS 16.6, tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. A website may be able to
    bypass Same Origin Policy. (CVE-2023-38572)

  - A logic issue was addressed with improved restrictions. This issue is fixed in iOS 16.6 and iPadOS 16.6,
    watchOS 9.6, tvOS 16.6, macOS Ventura 13.5. Processing web content may lead to arbitrary code execution.
    (CVE-2023-38592)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.8 and iPadOS 15.7.8, iOS
    16.6 and iPadOS 16.6, tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may
    lead to arbitrary code execution. (CVE-2023-38594)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.6 and iPadOS 16.6, tvOS 16.6,
    macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may lead to arbitrary code execution.
    (CVE-2023-38595, CVE-2023-38600)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.8 and iPadOS 15.7.8, iOS
    16.6 and iPadOS 16.6, macOS Ventura 13.5, Safari 16.6. Processing web content may lead to arbitrary code
    execution. (CVE-2023-38597)

  - A logic issue was addressed with improved state management. This issue is fixed in Safari 16.6, watchOS
    9.6, iOS 15.7.8 and iPadOS 15.7.8, tvOS 16.6, iOS 16.6 and iPadOS 16.6, macOS Ventura 13.5. A website may
    be able to track sensitive user information. (CVE-2023-38599)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 16.6 and iPadOS 16.6,
    tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may lead to arbitrary code
    execution. (CVE-2023-38611)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in iOS 17 and
    iPadOS 17, watchOS 10, macOS Sonoma 14. Processing web content may lead to arbitrary code execution.
    (CVE-2023-39434)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.5. A remote attacker
    may be able to cause arbitrary javascript code execution. (CVE-2023-40397)

  - This issue was addressed with improved iframe sandbox enforcement. This issue is fixed in Safari 17. An
    attacker with JavaScript execution may be able to execute arbitrary code. (CVE-2023-40451)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:7055");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40451");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-40397");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'webkit2gtk3-2.40.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.40.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.40.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.40.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.40.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.40.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.40.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.40.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'webkit2gtk3 / webkit2gtk3-devel / webkit2gtk3-jsc / etc');
}
