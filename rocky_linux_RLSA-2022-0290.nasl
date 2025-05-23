#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:0290.
##

include('compat.inc');

if (description)
{
  script_id(184625);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id(
    "CVE-2021-4104",
    "CVE-2022-23302",
    "CVE-2022-23305",
    "CVE-2022-23307"
  );
  script_xref(name:"RLSA", value:"2022:0290");

  script_name(english:"Rocky Linux 8 : parfait:0.5 (RLSA-2022:0290)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2022:0290 advisory.

  - JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write
    access to the Log4j configuration. The attacker can provide TopicBindingName and
    TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result
    in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2
    when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of
    life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the
    previous versions. (CVE-2021-4104)

  - JMSSink in all versions of Log4j 1.x is vulnerable to deserialization of untrusted data when the attacker
    has write access to the Log4j configuration or if the configuration references an LDAP service the
    attacker has access to. The attacker can provide a TopicConnectionFactoryBindingName configuration causing
    JMSSink to perform JNDI requests that result in remote code execution in a similar fashion to
    CVE-2021-4104. Note this issue only affects Log4j 1.x when specifically configured to use JMSSink, which
    is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2
    as it addresses numerous other issues from the previous versions. (CVE-2022-23302)

  - By design, the JDBCAppender in Log4j 1.2.x accepts an SQL statement as a configuration parameter where the
    values to be inserted are converters from PatternLayout. The message converter, %m, is likely to always be
    included. This allows attackers to manipulate the SQL by entering crafted strings into input fields or
    headers of an application that are logged allowing unintended SQL queries to be executed. Note this issue
    only affects Log4j 1.x when specifically configured to use the JDBCAppender, which is not the default.
    Beginning in version 2.0-beta8, the JDBCAppender was re-introduced with proper support for parameterized
    SQL queries and further customization over the columns written to in logs. Apache Log4j 1.2 reached end of
    life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the
    previous versions. (CVE-2022-23305)

  - CVE-2020-9493 identified a deserialization issue that was present in Apache Chainsaw. Prior to Chainsaw
    V2.0 Chainsaw was a component of Apache Log4j 1.2.x where the same issue exists. (CVE-2022-23307)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:0290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2031667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2041949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2041959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2041967");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23307");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23305");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:parfait");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:parfait-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:parfait-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pcp-parfait-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:si-units");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:si-units-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:unit-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:unit-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:uom-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:uom-lib-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:uom-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:uom-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:uom-se-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:uom-systems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:uom-systems-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var module_ver = get_kb_item('Host/RockyLinux/appstream/parfait');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module parfait:0.5');
if ('0.5' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module parfait:' + module_ver);

var appstreams = {
    'parfait:0.5': [
      {'reference':'parfait-0.5.4-4.module+el8.5.0+728+553fbdb8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'parfait-examples-0.5.4-4.module+el8.5.0+728+553fbdb8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'parfait-javadoc-0.5.4-4.module+el8.5.0+728+553fbdb8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-parfait-agent-0.5.4-4.module+el8.5.0+728+553fbdb8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'si-units-0.6.5-2.module+el8.3.0+214+edf13b3f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'si-units-javadoc-0.6.5-2.module+el8.3.0+214+edf13b3f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'unit-api-1.0-5.module+el8.3.0+214+edf13b3f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'unit-api-javadoc-1.0-5.module+el8.3.0+214+edf13b3f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-lib-1.0.1-6.module+el8.3.0+214+edf13b3f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-lib-javadoc-1.0.1-6.module+el8.3.0+214+edf13b3f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-parent-1.0.3-3.module+el8.3.0+214+edf13b3f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-se-1.0.4-3.module+el8.3.0+214+edf13b3f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-se-javadoc-1.0.4-3.module+el8.3.0+214+edf13b3f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-systems-0.7-1.module+el8.3.0+214+edf13b3f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-systems-javadoc-0.7-1.module+el8.3.0+214+edf13b3f', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RockyLinux/appstream/' + appstream_name);
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
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module parfait:0.5');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'parfait / parfait-examples / parfait-javadoc / pcp-parfait-agent / etc');
}
