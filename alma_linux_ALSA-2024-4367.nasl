#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:4367.
##

include('compat.inc');

if (description)
{
  script_id(202066);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id("CVE-2023-4727");
  script_xref(name:"ALSA", value:"2024:4367");

  script_name(english:"AlmaLinux 8 : pki-core (ALSA-2024:4367)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2024:4367 advisory.

    * dogtag ca: token authentication bypass vulnerability (CVE-2023-4727)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-4367.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4727");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(305);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-jss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-jss-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-ldapjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-ldapjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-pki-acme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-pki-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:idm-tomcatjss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-idm-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:resteasy-javadoc");
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

var module_ver = get_kb_item('Host/AlmaLinux/appstream/pki-core');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-core:10.6');
if ('10.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module pki-core:' + module_ver);

var appstreams = {
    'pki-core:10.6': [
      {'reference':'idm-jss-4.11.0-1.module_el8.10.0+3801+17b19a60', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-4.11.0-1.module_el8.10.0+3801+17b19a60', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-4.11.0-1.module_el8.10.0+3801+17b19a60', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-4.11.0-1.module_el8.10.0+3801+17b19a60', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-javadoc-4.11.0-1.module_el8.10.0+3801+17b19a60', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-javadoc-4.11.0-1.module_el8.10.0+3801+17b19a60', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-javadoc-4.11.0-1.module_el8.10.0+3801+17b19a60', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-javadoc-4.11.0-1.module_el8.10.0+3801+17b19a60', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-ldapjdk-4.24.0-1.module_el8.10.0+3801+17b19a60', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-ldapjdk-javadoc-4.24.0-1.module_el8.10.0+3801+17b19a60', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-acme-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-base-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-base-java-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-ca-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-kra-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-server-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-symkey-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-symkey-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-symkey-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-symkey-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-tools-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-tools-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-tools-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-tools-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-tomcatjss-7.8.0-1.module_el8.10.0+3801+17b19a60', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-idm-pki-10.15.1-1.module_el8.10.0+3868+cdab0fd8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-3.0.26-7.module_el8.10.0+3808+9d4ab1fb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-javadoc-3.0.26-7.module_el8.10.0+3808+9d4ab1fb', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-core:10.6');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idm-jss / idm-jss-javadoc / idm-ldapjdk / idm-ldapjdk-javadoc / etc');
}
