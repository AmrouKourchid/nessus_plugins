#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:0861.
##

include('compat.inc');

if (description)
{
  script_id(190898);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id("CVE-2023-44442", "CVE-2023-44444");
  script_xref(name:"ALSA", value:"2024:0861");

  script_name(english:"AlmaLinux 8 : gimp:2.8 (ALSA-2024:0861)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:0861 advisory.

    * gimp: PSD buffer overflow RCE (CVE-2023-44442)
    * gimp: psp off-by-one RCE (CVE-2023-44444)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-0861.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44444");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 193);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gimp-devel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gimp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pygobject2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pygobject2-codegen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pygobject2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pygobject2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pygtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pygtk2-codegen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pygtk2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pygtk2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python2-cairo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python2-cairo-devel");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/gimp');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module gimp:2.8');
if ('2.8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module gimp:' + module_ver);

var appstreams = {
    'gimp:2.8': [
      {'reference':'gimp-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-devel-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-devel-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-devel-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-devel-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-devel-tools-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-devel-tools-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-devel-tools-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-devel-tools-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-libs-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-libs-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-libs-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'gimp-libs-2.8.22-25.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'pygobject2-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-codegen-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-codegen-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-codegen-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-codegen-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-devel-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-devel-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-devel-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-devel-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-doc-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-doc-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-doc-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygobject2-doc-2.28.7-4.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-2.24.0-25.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-2.24.0-25.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-2.24.0-25.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-2.24.0-25.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-codegen-2.24.0-25.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-codegen-2.24.0-25.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-codegen-2.24.0-25.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-codegen-2.24.0-25.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-devel-2.24.0-25.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-devel-2.24.0-25.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-devel-2.24.0-25.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-devel-2.24.0-25.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pygtk2-doc-2.24.0-25.module_el8.9.0+3725+d1441900', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-cairo-1.16.3-6.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-cairo-1.16.3-6.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-cairo-1.16.3-6.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-cairo-1.16.3-6.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-cairo-devel-1.16.3-6.module_el8.9.0+3725+d1441900', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-cairo-devel-1.16.3-6.module_el8.9.0+3725+d1441900', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-cairo-devel-1.16.3-6.module_el8.9.0+3725+d1441900', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-cairo-devel-1.16.3-6.module_el8.9.0+3725+d1441900', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module gimp:2.8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gimp / gimp-devel / gimp-devel-tools / gimp-libs / pygobject2 / etc');
}
