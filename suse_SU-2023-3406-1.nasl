#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3406-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(180149);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/24");

  script_cve_id(
    "CVE-2022-40609",
    "CVE-2023-22006",
    "CVE-2023-22036",
    "CVE-2023-22041",
    "CVE-2023-22044",
    "CVE-2023-22045",
    "CVE-2023-22049",
    "CVE-2023-25193"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3406-1");

  script_name(english:"SUSE SLES12 Security Update : java-1_8_0-ibm (SUSE-SU-2023:3406-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:3406-1 advisory.

  - IBM SDK, Java Technology Edition 7.1.5.18 and 8.0.8.0 could allow a remote attacker to execute arbitrary
    code on the system, caused by an unsafe deserialization flaw. By sending specially-crafted data, an
    attacker could exploit this vulnerability to execute arbitrary code on the system. IBM X-Force ID: 236069.
    (CVE-2022-40609)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK product of
    Oracle Java SE (component: Networking). Supported versions that are affected are Oracle Java SE: 11.0.19,
    17.0.7, 20.0.1; Oracle GraalVM Enterprise Edition: 20.3.10, 21.3.6, 22.3.2; Oracle GraalVM for JDK: 17.0.7
    and 20.0.1. Difficult to exploit vulnerability allows unauthenticated attacker with network access via
    multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for
    JDK. Successful attacks require human interaction from a person other than the attacker. Successful
    attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle
    Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2023-22006)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK product of
    Oracle Java SE (component: Utility). Supported versions that are affected are Oracle Java SE: 11.0.19,
    17.0.7, 20.0.1; Oracle GraalVM Enterprise Edition: 20.3.10, 21.3.6, 22.3.2; Oracle GraalVM for JDK: 17.0.7
    and 20.0.1. Difficult to exploit vulnerability allows unauthenticated attacker with network access via
    multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for
    JDK. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial
    of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK.
    Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web
    service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security.
    (CVE-2023-22036)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK product of
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u371-perf,
    11.0.19, 17.0.7, 20.0.1; Oracle GraalVM Enterprise Edition: 20.3.10, 21.3.6, 22.3.2; Oracle GraalVM for
    JDK: 17.0.7 and 20.0.1. Difficult to exploit vulnerability allows unauthenticated attacker with logon to
    the infrastructure where Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK
    executes to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK accessible data.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2023-22041)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK product of
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u371-perf,
    17.0.7, 20.0.1; Oracle GraalVM Enterprise Edition: 21.3.6, 22.3.2; Oracle GraalVM for JDK: 17.0.7 and
    20.0.1. Difficult to exploit vulnerability allows unauthenticated attacker with network access via
    multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for
    JDK. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle
    Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK accessible data. Note: This
    vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which
    supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on the Java sandbox for security. (CVE-2023-22044)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK product of
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u371,
    8u371-perf, 11.0.19, 17.0.7, 20.0.1; Oracle GraalVM Enterprise Edition: 20.3.10, 21.3.6, 22.3.2; Oracle
    GraalVM for JDK: 17.0.7 and 20.0.1. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise
    Edition, Oracle GraalVM for JDK. Successful attacks of this vulnerability can result in unauthorized read
    access to a subset of Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK accessible
    data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a
    web service which supplies data to the APIs. This vulnerability also applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. (CVE-2023-22045)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle GraalVM for JDK product of
    Oracle Java SE (component: Libraries). Supported versions that are affected are Oracle Java SE: 8u371,
    8u371-perf, 11.0.19, 17.0.7, 20.0.1; Oracle GraalVM Enterprise Edition: 20.3.10, 21.3.6, 22.3.2; Oracle
    GraalVM for JDK: 17.0.7 and 20.0.1. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise
    Edition, Oracle GraalVM for JDK. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle
    GraalVM for JDK accessible data. Note: This vulnerability can be exploited by using APIs in the specified
    Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. (CVE-2023-22049)

  - hb-ot-layout-gsubgpos.hh in HarfBuzz through 6.0.0 allows attackers to trigger O(n^2) growth via
    consecutive marks during the process of looking back for base glyphs when attaching marks.
    (CVE-2023-25193)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214431");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-August/031141.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22036");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25193");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1_8_0-ibm, java-1_8_0-ibm-alsa, java-1_8_0-ibm-devel and / or java-1_8_0-ibm-plugin packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40609");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-30.114.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-30.114.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-30.114.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-30.114.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-30.114.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-30.114.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-30.114.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-30.114.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1_8_0-ibm / java-1_8_0-ibm-alsa / java-1_8_0-ibm-devel / etc');
}
