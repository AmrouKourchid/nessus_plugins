##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:1860.
##

include('compat.inc');

if (description)
{
  script_id(161090);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id("CVE-2020-13956");
  script_xref(name:"ALSA", value:"2022:1860");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"AlmaLinux 8 : maven:3.6 (ALSA-2022:1860)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2022:1860 advisory.

    * apache-httpclient: incorrect handling of malformed authority component in request URIs (CVE-2020-13956)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-1860.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13956");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:aopalliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:apache-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:apache-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:apache-commons-lang3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:atinject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:cdi-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:geronimo-annotation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:google-guice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:guava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpcomponents-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:jansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:jcl-over-slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:jsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:jsr-305");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:maven");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:maven-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:maven-openjdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:maven-openjdk17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:maven-openjdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:maven-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:maven-shared-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:maven-wagon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:plexus-cipher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:plexus-classworlds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:plexus-containers-component-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:plexus-interpolation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:plexus-sec-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:plexus-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:sisu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var module_ver = get_kb_item('Host/AlmaLinux/appstream/maven');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module maven:3.6');
if ('3.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module maven:' + module_ver);

var appstreams = {
    'maven:3.6': [
      {'reference':'aopalliance-1.0-20.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-cli-1.4-7.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-codec-1.13-3.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-io-2.6-6.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'apache-commons-lang3-3.9-4.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'atinject-1-31.20100611svn86.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cdi-api-2.0.1-3.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'geronimo-annotation-1.0-26.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'google-guice-4.2.2-4.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'guava-28.1-3.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpcomponents-client-4.5.10-4.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpcomponents-core-4.4.12-3.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jansi-1.18-4.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jcl-over-slf4j-1.7.28-3.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jsoup-1.12.1-3.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jsr-305-0-0.25.20130910svn.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-3.6.2-7.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-lib-3.6.2-7.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-openjdk11-3.6.2-7.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-openjdk17-3.6.2-7.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-openjdk8-3.6.2-7.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-1.4.1-3.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-shared-utils-3.2.1-0.4.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-wagon-3.3.4-2.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-cipher-1.7-17.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-classworlds-2.6.0-4.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-containers-component-annotations-2.1.0-2.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-interpolation-1.26-3.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-sec-dispatcher-1.4-29.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-utils-3.3.0-3.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sisu-0.3.4-2.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-1.7.28-3.module_el8.6.0+2786+d7c38b21', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module maven:3.6');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aopalliance / apache-commons-cli / apache-commons-codec / etc');
}
