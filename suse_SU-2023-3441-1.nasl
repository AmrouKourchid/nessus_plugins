#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3441-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(180313);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/01");

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
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3441-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : java-1_8_0-ibm (SUSE-SU-2023:3441-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:3441-1 advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214431");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-August/016025.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7aef02ba");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22036");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25193");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40609");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.4|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1/2/3/4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(1|2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP1/2/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-legacy-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-legacy-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-legacy-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-legacy-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-legacy-release-15.5', 'sles-release-15.5']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-legacy-release-15.5', 'sles-release-15.5']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-legacy-release-15.5', 'sles-release-15.5']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-legacy-release-15.5', 'sles-release-15.5']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'java-1_8_0-ibm-32bit-1.8.0_sr8.10-150000.3.80.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'java-1_8_0-ibm-demo-1.8.0_sr8.10-150000.3.80.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'java-1_8_0-ibm-devel-32bit-1.8.0_sr8.10-150000.3.80.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'java-1_8_0-ibm-src-1.8.0_sr8.10-150000.3.80.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'java-1_8_0-ibm-32bit-1.8.0_sr8.10-150000.3.80.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'java-1_8_0-ibm-demo-1.8.0_sr8.10-150000.3.80.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'java-1_8_0-ibm-devel-32bit-1.8.0_sr8.10-150000.3.80.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'java-1_8_0-ibm-src-1.8.0_sr8.10-150000.3.80.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'java-1_8_0-ibm-alsa-1.8.0_sr8.10-150000.3.80.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'java-1_8_0-ibm-plugin-1.8.0_sr8.10-150000.3.80.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'java-1_8_0-ibm-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'java-1_8_0-ibm-devel-1.8.0_sr8.10-150000.3.80.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1_8_0-ibm / java-1_8_0-ibm-32bit / java-1_8_0-ibm-alsa / etc');
}
