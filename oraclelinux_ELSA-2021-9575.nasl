#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9575.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155926);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2021-41617");
  script_xref(name:"IAVA", value:"2021-A-0474-S");

  script_name(english:"Oracle Linux 7 : openssh (ELSA-2021-9575)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2021-9575 advisory.

    [7.4p1-22.0.1_fips]
    - Change Epoch from 1 to 10
    - Enable fips KDF POST [Orabug: 32461750]
    - Disable diffie-hellman-group-exchange-sha256 KEX FIPS method [Orabug: 32461739]

    [7.4p1-22.0.1]
    - enlarge format buffer size for certificate serial
      number so the log message can record any 64-bit integer without
      truncation (openssh bz#3012) [Orabug: 30448895]

    [7.4p1-22 + 0.10.3-2]
    - avoid segfault in Kerberos cache cleanup (#1999263)
    - fix CVE-2021-41617 (#2008884)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9575.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41617");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-server-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'openssh-7.4p1-22.0.1.el7_9_fips', 'cpu':'aarch64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-askpass-7.4p1-22.0.1.el7_9_fips', 'cpu':'aarch64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-cavs-7.4p1-22.0.1.el7_9_fips', 'cpu':'aarch64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-clients-7.4p1-22.0.1.el7_9_fips', 'cpu':'aarch64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-keycat-7.4p1-22.0.1.el7_9_fips', 'cpu':'aarch64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-ldap-7.4p1-22.0.1.el7_9_fips', 'cpu':'aarch64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-server-7.4p1-22.0.1.el7_9_fips', 'cpu':'aarch64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-server-sysvinit-7.4p1-22.0.1.el7_9_fips', 'cpu':'aarch64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'pam_ssh_agent_auth-0.10.3-2.22.0.1.el7_9_fips', 'cpu':'aarch64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'pam_ssh_agent_auth-0.10.3-2.22.0.1.el7_9_fips', 'cpu':'i686', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'openssh-7.4p1-22.0.1.el7_9_fips', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-askpass-7.4p1-22.0.1.el7_9_fips', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-cavs-7.4p1-22.0.1.el7_9_fips', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-clients-7.4p1-22.0.1.el7_9_fips', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-keycat-7.4p1-22.0.1.el7_9_fips', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-ldap-7.4p1-22.0.1.el7_9_fips', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-server-7.4p1-22.0.1.el7_9_fips', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'openssh-server-sysvinit-7.4p1-22.0.1.el7_9_fips', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'allowmaj':TRUE},
    {'reference':'pam_ssh_agent_auth-0.10.3-2.22.0.1.el7_9_fips', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9_fips', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssh / openssh-askpass / openssh-cavs / etc');
}
