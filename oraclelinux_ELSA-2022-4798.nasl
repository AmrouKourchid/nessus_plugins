##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-4798.
##

include('compat.inc');

if (description)
{
  script_id(161767);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2022-29599");
  script_xref(name:"IAVA", value:"2023-A-0559");

  script_name(english:"Oracle Linux 8 : maven:3.5 (ELSA-2022-4798)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2022-4798 advisory.

    maven-shared-utils
    [3.2.1-0.2]
    - Fix commandline injection vulnerability
    - Resolves: CVE-2022-29599

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-4798.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29599");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:aopalliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-lang3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:atinject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cdi-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:geronimo-annotation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glassfish-el-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:google-guice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:guava20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hawtjni-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpcomponents-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jansi-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jboss-interceptors-1.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jcl-over-slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-resolver-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-resolver-connector-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-resolver-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-resolver-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-resolver-transport-wagon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-resolver-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-shared-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-wagon-file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-wagon-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-wagon-http-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-wagon-provider-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plexus-cipher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plexus-classworlds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plexus-containers-component-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plexus-interpolation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plexus-sec-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plexus-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sisu-inject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sisu-plexus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slf4j");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/maven');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module maven:3.5');
if ('3.5' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module maven:' + module_ver);

var appstreams = {
    'maven:3.5': [
      {'reference':'aopalliance-1.0-17.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-cli-1.4-4.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-codec-1.11-3.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-io-2.6-3.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'apache-commons-lang3-3.7-3.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-logging-1.2-13.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'atinject-1-28.20100611svn86.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cdi-api-1.2-8.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'geronimo-annotation-1.0-23.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-el-api-3.0.1-0.7.b08.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'google-guice-4.1-11.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'guava20-20.0-8.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hawtjni-runtime-1.16-2.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpcomponents-client-4.5.5-5.module+el8.6.0+20537+63b96daa', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpcomponents-core-4.4.10-3.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jansi-1.17.1-1.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jansi-native-1.7-7.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-interceptors-1.2-api-1.0.0-8.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jcl-over-slf4j-1.7.25-4.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jsoup-1.11.3-3.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-3.5.4-5.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-lib-3.5.4-5.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-api-1.1.1-2.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-connector-basic-1.1.1-2.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-impl-1.1.1-2.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-spi-1.1.1-2.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-transport-wagon-1.1.1-2.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-util-1.1.1-2.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-shared-utils-3.2.1-0.2.module+el8.6.0+20674+d36d0344', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-wagon-file-3.1.0-1.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-wagon-http-3.1.0-1.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-wagon-http-shared-3.1.0-1.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-wagon-provider-api-3.1.0-1.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-cipher-1.7-14.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-classworlds-2.5.2-9.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-containers-component-annotations-1.7.1-8.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-interpolation-1.22-9.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-sec-dispatcher-1.4-26.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-utils-3.1.0-3.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sisu-inject-0.3.3-6.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sisu-plexus-0.3.3-6.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'slf4j-1.7.25-4.module+el8+5161+5cac467c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpcomponents-client-4.5.5-5.module+el8.6.0+20537+63b96daa', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jansi-native-1.7-7.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-interceptors-1.2-api-1.0.0-8.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jcl-over-slf4j-1.7.25-4.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jsoup-1.11.3-3.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-3.5.4-5.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-lib-3.5.4-5.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-api-1.1.1-2.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-connector-basic-1.1.1-2.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-impl-1.1.1-2.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-spi-1.1.1-2.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-transport-wagon-1.1.1-2.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-util-1.1.1-2.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-shared-utils-3.2.1-0.2.module+el8.6.0+20674+d36d0344', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-wagon-file-3.1.0-1.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-wagon-http-3.1.0-1.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-wagon-http-shared-3.1.0-1.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-wagon-provider-api-3.1.0-1.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-cipher-1.7-14.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-classworlds-2.5.2-9.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-containers-component-annotations-1.7.1-8.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-interpolation-1.22-9.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-sec-dispatcher-1.4-26.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-utils-3.1.0-3.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sisu-inject-0.3.3-6.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sisu-plexus-0.3.3-6.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'slf4j-1.7.25-4.module+el8+5161+5cac467c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
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
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module maven:3.5');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aopalliance / apache-commons-cli / apache-commons-codec / etc');
}
