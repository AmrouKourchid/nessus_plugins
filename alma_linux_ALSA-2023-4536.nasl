#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:4536.
##

include('compat.inc');

if (description)
{
  script_id(179625);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id(
    "CVE-2023-30581",
    "CVE-2023-30588",
    "CVE-2023-30589",
    "CVE-2023-30590"
  );
  script_xref(name:"ALSA", value:"2023:4536");

  script_name(english:"AlmaLinux 8 : nodejs:18 (ALSA-2023:4536)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:4536 advisory.

    * nodejs: mainModule.proto bypass experimental policy mechanism (CVE-2023-30581)
    * nodejs: process interuption due to invalid Public Key information in x509 certificates (CVE-2023-30588)
    * nodejs: HTTP Request Smuggling via Empty headers separated by CR (CVE-2023-30589)
    * nodejs: DiffieHellman do not generate keys after setting a private key (CVE-2023-30590)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-4536.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30590");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-packaging-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/nodejs');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:18');
if ('18' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module nodejs:' + module_ver);

var appstreams = {
    'nodejs:18': [
      {'reference':'nodejs-18.16.1-1.module_el8.8.0+3595+0818e803', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-18.16.1-1.module_el8.8.0+3595+0818e803', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-18.16.1-1.module_el8.8.0+3595+0818e803', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-18.16.1-1.module_el8.8.0+3595+0818e803', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-18.16.1-1.module_el8.8.0+3595+0818e803', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-18.16.1-1.module_el8.8.0+3595+0818e803', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-18.16.1-1.module_el8.8.0+3595+0818e803', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-18.16.1-1.module_el8.8.0+3595+0818e803', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-docs-18.16.1-1.module_el8.8.0+3595+0818e803', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-18.16.1-1.module_el8.8.0+3595+0818e803', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-18.16.1-1.module_el8.8.0+3595+0818e803', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-18.16.1-1.module_el8.8.0+3595+0818e803', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-18.16.1-1.module_el8.8.0+3595+0818e803', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-nodemon-2.0.20-2.module_el8.8.0+3587+ee652244', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nodejs-packaging-2021.06-4.module_el8.7.0+3343+ea2b7901', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nodejs-packaging-bundler-2021.06-4.module_el8.7.0+3343+ea2b7901', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'npm-9.5.1-1.18.16.1.1.module_el8.8.0+3595+0818e803', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'npm-9.5.1-1.18.16.1.1.module_el8.8.0+3595+0818e803', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'npm-9.5.1-1.18.16.1.1.module_el8.8.0+3595+0818e803', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'npm-9.5.1-1.18.16.1.1.module_el8.8.0+3595+0818e803', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:18');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-devel / nodejs-docs / nodejs-full-i18n / etc');
}
