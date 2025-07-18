#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-f60cca0686
#

include('compat.inc');

if (description)
{
  script_id(170920);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2022-44566",
    "CVE-2023-22792",
    "CVE-2023-22794",
    "CVE-2023-22795",
    "CVE-2023-22796",
    "CVE-2023-22797"
  );
  script_xref(name:"FEDORA", value:"2023-f60cca0686");

  script_name(english:"Fedora 38 : rubygem-actioncable / rubygem-actionmailbox / rubygem-actionmailer / etc (2023-f60cca0686)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2023-f60cca0686 advisory.

    Upgrade to Ruby on Rails 7.0.4.2. Fixes numerous CVEs: https://rubyonrails.org/2023/1/17/Rails-
    Versions-6-0-6-1-6-1-7-1-7-0-4-1-have-been-released

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-f60cca0686");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22794");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actioncable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actionmailbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actiontext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actionview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activejob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activestorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-railties");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'rubygem-actioncable-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-actionmailbox-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-actionmailer-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'rubygem-actionpack-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'rubygem-actiontext-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-actionview-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-activejob-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-activemodel-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-activerecord-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'rubygem-activestorage-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-activesupport-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'rubygem-rails-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'rubygem-railties-7.0.4.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rubygem-actioncable / rubygem-actionmailbox / rubygem-actionmailer / etc');
}
