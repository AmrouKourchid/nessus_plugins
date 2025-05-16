#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2906-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(178695);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/21");

  script_cve_id(
    "CVE-2017-18267",
    "CVE-2018-13988",
    "CVE-2018-16646",
    "CVE-2018-18897",
    "CVE-2018-19058",
    "CVE-2018-19059",
    "CVE-2018-19060",
    "CVE-2018-19149",
    "CVE-2018-20481",
    "CVE-2018-20650",
    "CVE-2018-21009",
    "CVE-2019-7310",
    "CVE-2022-27337"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2906-1");

  script_name(english:"SUSE SLES12 Security Update : poppler (SUSE-SU-2023:2906-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has a package installed that is affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:2906-1 advisory.

  - The FoFiType1C::cvtGlyph function in fofi/FoFiType1C.cc in Poppler through 0.64.0 allows remote attackers
    to cause a denial of service (infinite recursion) via a crafted PDF file, as demonstrated by pdftops.
    (CVE-2017-18267)

  - Poppler through 0.62 contains an out of bounds read vulnerability due to an incorrect memory access that
    is not mapped in its memory space, as demonstrated by pdfunite. This can result in memory corruption and
    denial of service. This may be exploitable when a victim opens a specially crafted PDF file.
    (CVE-2018-13988)

  - In Poppler 0.68.0, the Parser::getObj() function in Parser.cc may cause infinite recursion via a crafted
    file. A remote attacker can leverage this for a DoS attack. (CVE-2018-16646)

  - An issue was discovered in Poppler 0.71.0. There is a memory leak in GfxColorSpace::setDisplayProfile in
    GfxState.cc, as demonstrated by pdftocairo. (CVE-2018-18897)

  - An issue was discovered in Poppler 0.71.0. There is a reachable abort in Object.h, will lead to denial of
    service because EmbFile::save2 in FileSpec.cc lacks a stream check before saving an embedded file.
    (CVE-2018-19058)

  - An issue was discovered in Poppler 0.71.0. There is a out-of-bounds read in EmbFile::save2 in FileSpec.cc,
    will lead to denial of service, as demonstrated by utils/pdfdetach.cc not validating embedded files before
    save attempts. (CVE-2018-19059)

  - An issue was discovered in Poppler 0.71.0. There is a NULL pointer dereference in goo/GooString.h, will
    lead to denial of service, as demonstrated by utils/pdfdetach.cc not validating a filename of an embedded
    file before constructing a save path. (CVE-2018-19060)

  - Poppler before 0.70.0 has a NULL pointer dereference in _poppler_attachment_new when called from
    poppler_annot_file_attachment_get_attachment. (CVE-2018-19149)

  - XRef::getEntry in XRef.cc in Poppler 0.72.0 mishandles unallocated XRef entries, which allows remote
    attackers to cause a denial of service (NULL pointer dereference) via a crafted PDF document, when
    XRefEntry::setFlag in XRef.h is called from Parser::makeStream in Parser.cc. (CVE-2018-20481)

  - A reachable Object::dictLookup assertion in Poppler 0.72.0 allows attackers to cause a denial of service
    due to the lack of a check for the dict data type, as demonstrated by use of the FileSpec class (in
    FileSpec.cc) in pdfdetach. (CVE-2018-20650)

  - Poppler before 0.66.0 has an integer overflow in Parser::makeStream in Parser.cc. (CVE-2018-21009)

  - In Poppler 0.73.0, a heap-based buffer over-read (due to an integer signedness error in the XRef::getEntry
    function in XRef.cc) allows remote attackers to cause a denial of service (application crash) or possibly
    have unspecified other impact via a crafted PDF document, as demonstrated by pdftocairo. (CVE-2019-7310)

  - A logic error in the Hints::Hints function of Poppler v22.03.0 allows attackers to cause a Denial of
    Service (DoS) via a crafted PDF file. (CVE-2022-27337)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1092945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1102531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1107597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1114966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1115185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1115186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1115187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1115626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1120939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1124150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199272");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-July/030447.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18267");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-13988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-18897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19149");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-21009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-7310");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-27337");
  script_set_attribute(attribute:"solution", value:
"Update the affected libpoppler44 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7310");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-21009");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpoppler44");
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
    {'reference':'libpoppler44-0.24.4-14.26.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libpoppler44-0.24.4-14.26.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpoppler44');
}
