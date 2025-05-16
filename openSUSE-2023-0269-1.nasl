#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0269-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(181919);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/27");

  script_cve_id(
    "CVE-2020-15598",
    "CVE-2021-42717",
    "CVE-2023-28882",
    "CVE-2023-38285"
  );

  script_name(english:"openSUSE 15 Security Update : modsecurity (openSUSE-SU-2023:0269-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0269-1 advisory.

  - ** DISPUTED ** Trustwave ModSecurity 3.x through 3.0.4 allows denial of service via a special request.
    NOTE: The discoverer reports Trustwave has signaled they are disputing our claims. The CVE suggests that
    there is a security issue with how ModSecurity handles regular expressions that can result in a Denial of
    Service condition. The vendor does not consider this as a security issue because1) there is no default
    configuration issue here. An attacker would need to know that a rule using a potentially problematic
    regular expression was in place, 2) the attacker would need to know the basic nature of the regular
    expression itself to exploit any resource issues. It's well known that regular expression usage can be
    taxing on system resources regardless of the use case. It is up to the administrator to decide on when it
    is appropriate to trade resources for potential security benefit. (CVE-2020-15598)

  - ModSecurity 3.x through 3.0.5 mishandles excessively nested JSON objects. Crafted JSON objects with
    nesting tens-of-thousands deep could result in the web server being unable to service legitimate requests.
    Even a moderately large (e.g., 300KB) HTTP request can occupy one of the limited NGINX worker processes
    for minutes and consume almost all of the available CPU on the machine. Modsecurity 2 is similarly
    vulnerable: the affected versions include 2.8.0 through 2.9.4. (CVE-2021-42717)

  - Trustwave ModSecurity 3.0.5 through 3.0.8 before 3.0.9 allows a denial of service (worker crash and
    unresponsiveness) because some inputs cause a segfault in the Transaction class for some configurations.
    (CVE-2023-28882)

  - Trustwave ModSecurity 3.x before 3.0.10 has Inefficient Algorithmic Complexity. (CVE-2023-38285)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213702");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ILAHCTDLNZCBSVGSQN2ZDHVDHYE2OZ2N/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80a7f7de");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42717");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38285");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42717");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-38285");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodsecurity3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodsecurity3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodsecurity3-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:modsecurity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:modsecurity-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
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
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'libmodsecurity3-3.0.10-bp154.2.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmodsecurity3-32bit-3.0.10-bp154.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmodsecurity3-64bit-3.0.10-bp154.2.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'modsecurity-3.0.10-bp154.2.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'modsecurity-devel-3.0.10-bp154.2.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmodsecurity3 / libmodsecurity3-32bit / libmodsecurity3-64bit / etc');
}
