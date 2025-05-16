#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:4084.
##

include('compat.inc');

if (description)
{
  script_id(200991);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/25");

  script_cve_id(
    "CVE-2024-32002",
    "CVE-2024-32004",
    "CVE-2024-32020",
    "CVE-2024-32021",
    "CVE-2024-32465"
  );
  script_xref(name:"ALSA", value:"2024:4084");

  script_name(english:"AlmaLinux 8 : git (ALSA-2024:4084)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:4084 advisory.

    * git: Recursive clones RCE (CVE-2024-32002)
    * git: RCE while cloning local repos (CVE-2024-32004)
    * git: additional local RCE (CVE-2024-32465)
    * git: insecure hardlinks (CVE-2024-32020)
    * git: symlink bypass (CVE-2024-32021)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-4084.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(114, 22, 434, 61, 62);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-credential-libsecret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-subtree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-Git-SVN");
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

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'git-2.43.5-1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-2.43.5-1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-all-2.43.5-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-2.43.5-1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-2.43.5-1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-doc-2.43.5-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-credential-libsecret-2.43.5-1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-credential-libsecret-2.43.5-1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-2.43.5-1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-2.43.5-1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-email-2.43.5-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-gui-2.43.5-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-instaweb-2.43.5-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-subtree-2.43.5-1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-subtree-2.43.5-1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-svn-2.43.5-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gitk-2.43.5-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gitweb-2.43.5-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Git-2.43.5-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Git-SVN-2.43.5-1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git / git-all / git-core / git-core-doc / git-credential-libsecret / etc');
}
