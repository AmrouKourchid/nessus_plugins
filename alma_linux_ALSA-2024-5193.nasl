#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:5193.
##

include('compat.inc');

if (description)
{
  script_id(205390);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id("CVE-2024-38476");
  script_xref(name:"ALSA", value:"2024:5193");

  script_name(english:"AlmaLinux 8 : httpd:2.4 (ALSA-2024:5193)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2024:5193 advisory.

    * httpd: Security issues via?backend applications whose response headers are malicious or exploitable
    (CVE-2024-38476)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-5193.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38476");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(829);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_ssl");
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

var module_ver = get_kb_item('Host/AlmaLinux/appstream/httpd');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module httpd:2.4');
if ('2.4' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module httpd:' + module_ver);

var appstreams = {
    'httpd:2.4': [
      {'reference':'httpd-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-devel-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-devel-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-devel-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-devel-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-filesystem-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-manual-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-tools-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-tools-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-tools-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'httpd-tools-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_http2-1.15.7-10.module_el8.10.0+3832+564e7653', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_http2-1.15.7-10.module_el8.10.0+3832+564e7653', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_http2-1.15.7-10.module_el8.10.0+3832+564e7653', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_http2-1.15.7-10.module_el8.10.0+3832+564e7653', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_ldap-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_ldap-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_ldap-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_ldap-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_md-2.0.8-8.module_el8.6.0+2872+fe0ff7aa', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_md-2.0.8-8.module_el8.6.0+2872+fe0ff7aa', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_md-2.0.8-8.module_el8.6.0+2872+fe0ff7aa', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_md-2.0.8-8.module_el8.6.0+2872+fe0ff7aa', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_proxy_html-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_proxy_html-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_proxy_html-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_proxy_html-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_session-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_session-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_session-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_session-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mod_ssl-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_ssl-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_ssl-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_ssl-2.4.37-65.module_el8.10.0+3874+c2064c23.2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module httpd:2.4');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd / httpd-devel / httpd-filesystem / httpd-manual / httpd-tools / etc');
}
