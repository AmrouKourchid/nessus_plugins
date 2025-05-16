#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:3166.
##

include('compat.inc');

if (description)
{
  script_id(235514);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id("CVE-2020-15778");
  script_xref(name:"RLSA", value:"2024:3166");

  script_name(english:"RockyLinux 8 : openssh (RLSA-2024:3166)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2024:3166 advisory.

    * openssh: scp allows command injection when using backtick characters in the destination argument
    (CVE-2020-15778)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:3166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1860487");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15778");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-askpass-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-cavs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-clients-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-keycat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssh-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pam_ssh_agent_auth-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'openssh-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-askpass-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-askpass-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-askpass-debuginfo-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-askpass-debuginfo-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-cavs-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-cavs-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-cavs-debuginfo-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-cavs-debuginfo-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-clients-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-clients-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-clients-debuginfo-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-clients-debuginfo-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-debuginfo-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-debuginfo-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-debugsource-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-debugsource-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-keycat-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-keycat-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-keycat-debuginfo-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-keycat-debuginfo-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-ldap-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-ldap-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-ldap-debuginfo-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-ldap-debuginfo-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-server-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-server-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-server-debuginfo-8.0p1-24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'openssh-server-debuginfo-8.0p1-24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'pam_ssh_agent_auth-0.10.3-7.24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pam_ssh_agent_auth-0.10.3-7.24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pam_ssh_agent_auth-debuginfo-0.10.3-7.24.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pam_ssh_agent_auth-debuginfo-0.10.3-7.24.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssh / openssh-askpass / openssh-askpass-debuginfo / etc');
}
