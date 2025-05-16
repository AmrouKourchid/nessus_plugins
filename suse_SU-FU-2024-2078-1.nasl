#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-SUSE-FU-2024:2078-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(200752);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/20");

  script_cve_id(
    "CVE-2021-22116",
    "CVE-2021-32718",
    "CVE-2021-32719",
    "CVE-2022-31008",
    "CVE-2023-46118"
  );
  script_xref(name:"SuSE", value:"SUSE-FU-2024:2078-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 : Feature update for rabbitmq-server313, erlang26, elixir115 (SUSE-SU-SUSE-FU-2024:2078-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-SUSE-FU-2024:2078-1 advisory.

    rabbitmq-server was implemented with a parallel versioned RPM package at version 3.13.1 (jsc#PED-8414):

    - Security issues fixed:

      * CVE-2021-22116: Fixed improper input validation that may lead to Denial of Sercice (DoS) attacks
    (bsc#1186203)
      * CVE-2021-32718, CVE-2021-32719: Fixed potential for JavaScript code execution in the management UI
        (bsc#1187818, bsc#1187819)
      * CVE-2022-31008: Fixed encryption key used to encrypt the URI was seeded with a predictable secret
    (bsc#1205267)
      * CVE-2023-46118: Fixed HTTP API vulnerability for denial of service (DoS) attacks with very large
    messages
        (bsc#1216582)

    - Other bugs fixed:

      * Fixed RabbitMQ maintenance status issue (bsc#1199431)
      * Provide user/group for RPM 4.19 (bsc#1219532)
      * Fixed `rabbitmqctl` command for `add_user` (bsc#1222591)
      * Added hardening to systemd service(s) (bsc#1181400)
      * Use /run instead of deprecated /var/run in tmpfiles.conf (bsc#1185075)

    - For the full list of upstream changes of this update between version 3.8.11 and 3.13.1 please consult:

      * https://www.rabbitmq.com/release-information

    erlang26:

    - Provide RPM package as it's a dependency of rabbitmq-server313 (jsc#PED-8414)

    elixir115:

    - Provide RPM package as needed in some cases by rabbitmq-server313 (jsc#PED-8414)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222591");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035642.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22116");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32718");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32719");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-46118");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32719");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-31008");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:elixir115");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:erlang-rabbitmq-client313");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:erlang26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:erlang26-epmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rabbitmq-server313");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rabbitmq-server313-plugins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'elixir115-1.15.7-150300.7.5.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'erlang-rabbitmq-client313-3.13.1-150600.13.5.3', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'erlang26-26.2.1-150300.7.5.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'erlang26-epmd-26.2.1-150300.7.5.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'rabbitmq-server313-3.13.1-150600.13.5.3', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'rabbitmq-server313-plugins-3.13.1-150600.13.5.3', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'elixir115-1.15.7-150300.7.5.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-server-applications-release-15.6', 'sles-release-15.6']},
    {'reference':'erlang-rabbitmq-client313-3.13.1-150600.13.5.3', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-server-applications-release-15.6', 'sles-release-15.6']},
    {'reference':'erlang26-26.2.1-150300.7.5.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-server-applications-release-15.6', 'sles-release-15.6']},
    {'reference':'erlang26-epmd-26.2.1-150300.7.5.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-server-applications-release-15.6', 'sles-release-15.6']},
    {'reference':'rabbitmq-server313-3.13.1-150600.13.5.3', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-server-applications-release-15.6', 'sles-release-15.6']},
    {'reference':'rabbitmq-server313-plugins-3.13.1-150600.13.5.3', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-server-applications-release-15.6', 'sles-release-15.6']},
    {'reference':'elixir115-1.15.7-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'elixir115-doc-1.15.7-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang-rabbitmq-client313-3.13.1-150600.13.5.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-debugger-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-debugger-src-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-dialyzer-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-dialyzer-src-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-diameter-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-diameter-src-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-doc-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-epmd-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-et-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-et-src-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-jinterface-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-jinterface-src-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-observer-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-observer-src-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-reltool-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-reltool-src-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-src-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-wx-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'erlang26-wx-src-26.2.1-150300.7.5.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'rabbitmq-server313-3.13.1-150600.13.5.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'rabbitmq-server313-plugins-3.13.1-150600.13.5.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'elixir115 / elixir115-doc / erlang-rabbitmq-client313 / erlang26 / etc');
}
