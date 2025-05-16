#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:0507.
##

include('compat.inc');

if (description)
{
  script_id(184826);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id("CVE-2020-17525");
  script_xref(name:"RLSA", value:"2021:0507");
  script_xref(name:"IAVA", value:"2021-A-0094-S");

  script_name(english:"Rocky Linux 8 : subversion:1.10 (RLSA-2021:0507)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2021:0507 advisory.

  - Subversion's mod_authz_svn module will crash if the server is using in-repository authz rules with the
    AuthzSVNReposRelativeAccessFile option and a client sends a request for a non-existing repository URL.
    This can lead to disruption for users of the service. This issue was fixed in mod_dav_svn+mod_authz_svn
    servers 1.14.1 and mod_dav_svn+mod_authz_svn servers 1.10.7 (CVE-2020-17525)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:0507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1922303");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17525");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libserf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libserf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libserf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_dav_svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:subversion-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:utf8proc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:utf8proc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:utf8proc-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var module_ver = get_kb_item('Host/RockyLinux/appstream/subversion');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module subversion:1.10');
if ('1.10' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module subversion:' + module_ver);

var appstreams = {
    'subversion:1.10': [
      {'reference':'libserf-1.3.9-9.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libserf-1.3.9-9.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libserf-1.3.9-9.module+el8.7.0+1065+42200b2e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libserf-1.3.9-9.module+el8.7.0+1065+42200b2e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libserf-debuginfo-1.3.9-9.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libserf-debuginfo-1.3.9-9.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libserf-debuginfo-1.3.9-9.module+el8.7.0+1065+42200b2e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libserf-debuginfo-1.3.9-9.module+el8.7.0+1065+42200b2e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libserf-debugsource-1.3.9-9.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libserf-debugsource-1.3.9-9.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libserf-debugsource-1.3.9-9.module+el8.7.0+1065+42200b2e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libserf-debugsource-1.3.9-9.module+el8.7.0+1065+42200b2e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_dav_svn-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_dav_svn-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_dav_svn-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_dav_svn-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-debugsource-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-debugsource-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-devel-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-devel-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-devel-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-devel-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-gnome-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-gnome-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-gnome-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-gnome-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-javahl-1.10.2-4.module+el8.4.0+407+38733e5a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-libs-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-libs-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-libs-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-libs-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-perl-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-perl-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-perl-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-perl-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-tools-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-tools-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-tools-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-tools-debuginfo-1.10.2-4.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'utf8proc-2.1.1-5.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'utf8proc-2.1.1-5.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'utf8proc-debuginfo-2.1.1-5.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'utf8proc-debuginfo-2.1.1-5.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'utf8proc-debugsource-2.1.1-5.module+el8.4.0+407+38733e5a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'utf8proc-debugsource-2.1.1-5.module+el8.4.0+407+38733e5a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module subversion:1.10');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libserf / libserf-debuginfo / libserf-debugsource / mod_dav_svn / etc');
}
