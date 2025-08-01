#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:7869.
##

include('compat.inc');

if (description)
{
  script_id(208765);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2024-38229",
    "CVE-2024-43483",
    "CVE-2024-43484",
    "CVE-2024-43485"
  );
  script_xref(name:"ALSA", value:"2024:7869");
  script_xref(name:"IAVA", value:"2024-A-0625-S");

  script_name(english:"AlmaLinux 9 : .NET 8.0 (ALSA-2024:7869)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:7869 advisory.

    * dotnet: kestrel: closing an HTTP/3 stream can cause a race condition and lead to remote code execution
    (CVE-2024-38229)
    * dotnet: Multiple .NET components susceptible to hash flooding (CVE-2024-43483)
    * dotnet: System.IO.Packaging - Multiple DoS vectors in use of SortedList (CVE-2024-43484)
    * dotnet: Denial of Service in System.Text.Json (CVE-2024-43485)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.Security Fix(es):

    * dotnet: System.IO.Packaging - Multiple DoS vectors in use of SortedList (CVE-2024-43484)
    * dotnet: Multiple .NET components susceptible to hash flooding (CVE-2024-43483)
    * dotnet: Denial of Service in System.Text.Json (CVE-2024-43485)
    * dotnet: kestrel: closing an HTTP/3 stream can cause a race condition and lead to remote code execution
    (CVE-2024-38229)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2024-7869.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43485");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(407, 416, 789);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:aspnetcore-runtime-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:aspnetcore-runtime-dbg-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:aspnetcore-targeting-pack-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:dotnet-apphost-pack-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:dotnet-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:dotnet-hostfxr-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:dotnet-runtime-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:dotnet-runtime-dbg-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:dotnet-sdk-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:dotnet-sdk-8.0-source-built-artifacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:dotnet-sdk-dbg-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:dotnet-targeting-pack-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:dotnet-templates-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netstandard-targeting-pack-2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'aspnetcore-runtime-8.0-8.0.10-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'aspnetcore-runtime-8.0-8.0.10-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'aspnetcore-runtime-8.0-8.0.10-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'aspnetcore-runtime-8.0-8.0.10-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'aspnetcore-runtime-dbg-8.0-8.0.10-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'aspnetcore-runtime-dbg-8.0-8.0.10-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'aspnetcore-runtime-dbg-8.0-8.0.10-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'aspnetcore-runtime-dbg-8.0-8.0.10-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'aspnetcore-targeting-pack-8.0-8.0.10-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'aspnetcore-targeting-pack-8.0-8.0.10-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'aspnetcore-targeting-pack-8.0-8.0.10-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'aspnetcore-targeting-pack-8.0-8.0.10-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-apphost-pack-8.0-8.0.10-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-apphost-pack-8.0-8.0.10-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-apphost-pack-8.0-8.0.10-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-apphost-pack-8.0-8.0.10-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-host-8.0.10-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-host-8.0.10-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-host-8.0.10-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-host-8.0.10-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-hostfxr-8.0-8.0.10-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-hostfxr-8.0-8.0.10-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-hostfxr-8.0-8.0.10-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-hostfxr-8.0-8.0.10-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-runtime-8.0-8.0.10-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-runtime-8.0-8.0.10-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-runtime-8.0-8.0.10-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-runtime-8.0-8.0.10-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-runtime-dbg-8.0-8.0.10-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-runtime-dbg-8.0-8.0.10-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-runtime-dbg-8.0-8.0.10-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-runtime-dbg-8.0-8.0.10-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-sdk-8.0-8.0.110-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-sdk-8.0-8.0.110-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-sdk-8.0-8.0.110-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-sdk-8.0-8.0.110-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-sdk-8.0-source-built-artifacts-8.0.110-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-sdk-8.0-source-built-artifacts-8.0.110-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-sdk-8.0-source-built-artifacts-8.0.110-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-sdk-8.0-source-built-artifacts-8.0.110-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-sdk-dbg-8.0-8.0.110-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-sdk-dbg-8.0-8.0.110-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-sdk-dbg-8.0-8.0.110-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-sdk-dbg-8.0-8.0.110-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-targeting-pack-8.0-8.0.10-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-targeting-pack-8.0-8.0.10-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-targeting-pack-8.0-8.0.10-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-targeting-pack-8.0-8.0.10-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-templates-8.0-8.0.110-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-templates-8.0-8.0.110-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-templates-8.0-8.0.110-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'dotnet-templates-8.0-8.0.110-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'netstandard-targeting-pack-2.1-8.0.110-1.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'netstandard-targeting-pack-2.1-8.0.110-1.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'netstandard-targeting-pack-2.1-8.0.110-1.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'netstandard-targeting-pack-2.1-8.0.110-1.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aspnetcore-runtime-8.0 / aspnetcore-runtime-dbg-8.0 / etc');
}
