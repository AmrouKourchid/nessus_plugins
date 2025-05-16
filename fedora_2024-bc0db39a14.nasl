#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-bc0db39a14
#

include('compat.inc');

if (description)
{
  script_id(194929);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/11");

  script_cve_id(
    "CVE-2024-26922",
    "CVE-2024-26924",
    "CVE-2024-26980",
    "CVE-2024-26981",
    "CVE-2024-26982",
    "CVE-2024-26983",
    "CVE-2024-26984",
    "CVE-2024-26985",
    "CVE-2024-26986",
    "CVE-2024-26987",
    "CVE-2024-26988",
    "CVE-2024-26989",
    "CVE-2024-26990",
    "CVE-2024-26991",
    "CVE-2024-26992",
    "CVE-2024-26993",
    "CVE-2024-26994",
    "CVE-2024-26995",
    "CVE-2024-26996",
    "CVE-2024-26998",
    "CVE-2024-26999",
    "CVE-2024-27000",
    "CVE-2024-27001",
    "CVE-2024-27002",
    "CVE-2024-27003",
    "CVE-2024-27004",
    "CVE-2024-27005",
    "CVE-2024-27006",
    "CVE-2024-27007",
    "CVE-2024-27008",
    "CVE-2024-27009",
    "CVE-2024-27010",
    "CVE-2024-27011",
    "CVE-2024-27012",
    "CVE-2024-27013",
    "CVE-2024-27014",
    "CVE-2024-27015",
    "CVE-2024-27016",
    "CVE-2024-27017",
    "CVE-2024-27018",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27021",
    "CVE-2024-27022"
  );
  script_xref(name:"FEDORA", value:"2024-bc0db39a14");

  script_name(english:"Fedora 39 : kernel (2024-bc0db39a14)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 39 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2024-bc0db39a14 advisory.

    The 6.8.8 stable kernel update contains a number of important fixes across the tree.



Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-bc0db39a14");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27022");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^39([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 39', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2024-26922', 'CVE-2024-26924', 'CVE-2024-26980', 'CVE-2024-26981', 'CVE-2024-26982', 'CVE-2024-26983', 'CVE-2024-26984', 'CVE-2024-26985', 'CVE-2024-26986', 'CVE-2024-26987', 'CVE-2024-26988', 'CVE-2024-26989', 'CVE-2024-26990', 'CVE-2024-26991', 'CVE-2024-26992', 'CVE-2024-26993', 'CVE-2024-26994', 'CVE-2024-26995', 'CVE-2024-26996', 'CVE-2024-26998', 'CVE-2024-26999', 'CVE-2024-27000', 'CVE-2024-27001', 'CVE-2024-27002', 'CVE-2024-27003', 'CVE-2024-27004', 'CVE-2024-27005', 'CVE-2024-27006', 'CVE-2024-27007', 'CVE-2024-27008', 'CVE-2024-27009', 'CVE-2024-27010', 'CVE-2024-27011', 'CVE-2024-27012', 'CVE-2024-27013', 'CVE-2024-27014', 'CVE-2024-27015', 'CVE-2024-27016', 'CVE-2024-27017', 'CVE-2024-27018', 'CVE-2024-27019', 'CVE-2024-27020', 'CVE-2024-27021', 'CVE-2024-27022');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for FEDORA-2024-bc0db39a14');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'reference':'kernel-6.8.8-200.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
