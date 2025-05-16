#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-2022.
##

include('compat.inc');

if (description)
{
  script_id(180866);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2018-16646",
    "CVE-2018-18897",
    "CVE-2018-19058",
    "CVE-2018-19059",
    "CVE-2018-19060",
    "CVE-2018-19149",
    "CVE-2018-20481",
    "CVE-2018-20650",
    "CVE-2018-20662",
    "CVE-2019-7310",
    "CVE-2019-9200",
    "CVE-2019-9631"
  );
  script_xref(name:"IAVB", value:"2018-B-0151-S");
  script_xref(name:"IAVB", value:"2019-B-0001-S");
  script_xref(name:"IAVB", value:"2019-B-0011-S");
  script_xref(name:"IAVB", value:"2019-B-0021-S");

  script_name(english:"Oracle Linux 7 : poppler (ELSA-2019-2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2019-2022 advisory.

    evince
    [3.28.2-8]
    - Do not free EvDocumentInfo in ev_window_save_print_settings(),
    - it is freed in EvDocuments destructor
    - Resolves: #1541358

    [3.28.2-7]
    - Do not store page-scaling for documents with enforced
    - page-scaling
    - Resolves: #1541358

    [3.28.2-6]
    - Use PrintScaling preference stored in PDFs
    - Resolves: #1541358

    okular
    [4.10.5-7]
    - Fix patch adding information about substituting font
      Resolves: bz#1458037

    [4.10.5-6]
    - Fix broken dependency on kde-runtime
      Resolves: bz#1670723

    [4.10.5-5]
    - Add information about substituting font
      Resolves: bz#1458037

    poppler
    [0.26.5-38]
    - Constrain number of cycles in rescale filter
    - Compute correct coverage values for box filter
    - Resolves: #1688417

    [0.26.5-37]
    - Fix tiling patterns when pattern cell is too far
    - Resolves: #1378961

    [0.26.5-36]
    - Fix version from which PrintScaling is available
    - Resolves: #1658304

    [0.26.5-35]
    - Export PrintScaling viewer preference in glib frontend
    - Related: #1658304

    [0.26.5-34]
    - Fix a memory leak detected by Coverity Scan
    - Related: #1636103

    [0.26.5-33]
    - Only embed mime data for gray/rgb/cmyk colorspaces
    - if image decode map is identity
    - Resolves: #1636103

    [0.26.5-32]
    - Fix possible crash on broken files in ImageStream::getLine()
    - Resolves: #1685267

    [0.26.5-31]
    - Avoid global display profile state becoming an uncontrolled
    - memory leak
    - Resolves: #1648860

    [0.26.5-30]
    - Check for missing pages in documents passed to pdfunite
    - Resolves: #1677348

    [0.26.5-29]
    - Dont reuse 'entry' in Parser::makeStream
    - Resolves: #1677058

    [0.26.5-28]
    - Move the fileSpec.dictLookup call inside fileSpec.isDict if
    - Resolves: #1677029

    [0.26.5-27]
    - Defend against requests for negative XRef indices
    - Resolves: #1673700

    [0.26.5-26]
    - Add font substituteName() getter to Qt bindings
    - Resolves: bz#1639595

    [0.26.5-25]
    - Check for valid file name of embedded file
    - Resolves: #1651307

    [0.26.5-24]
    - Check for valid embedded file before trying to save it
    - Resolves: #1651306

    [0.26.5-23]
    - Check for stream before calling stream methods
    - when saving an embedded file
    - Resolves: #1651305

    [0.26.5-22]
    - Fix crash on missing embedded file
    - Resolves: #1651309

    [0.26.5-21]
    - Avoid cycles in PDF parsing
    - Resolves: #1640295

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-2022.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9631");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-dvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:okular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:okular-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:okular-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:okular-part");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'evince-3.28.2-8.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-browser-plugin-3.28.2-8.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-devel-3.28.2-8.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-dvi-3.28.2-8.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-libs-3.28.2-8.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-nautilus-3.28.2-8.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'okular-4.10.5-7.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'okular-devel-4.10.5-7.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'okular-libs-4.10.5-7.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'okular-part-4.10.5-7.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-0.26.5-38.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-cpp-0.26.5-38.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-cpp-devel-0.26.5-38.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-demos-0.26.5-38.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-devel-0.26.5-38.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-glib-0.26.5-38.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-glib-devel-0.26.5-38.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-qt-0.26.5-38.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-qt-devel-0.26.5-38.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-utils-0.26.5-38.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-devel-3.28.2-8.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-dvi-3.28.2-8.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-libs-3.28.2-8.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-nautilus-3.28.2-8.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'okular-4.10.5-7.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'okular-devel-4.10.5-7.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'okular-libs-4.10.5-7.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'okular-part-4.10.5-7.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-0.26.5-38.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-cpp-0.26.5-38.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-cpp-devel-0.26.5-38.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-demos-0.26.5-38.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-devel-0.26.5-38.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-glib-0.26.5-38.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-glib-devel-0.26.5-38.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-qt-0.26.5-38.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-qt-devel-0.26.5-38.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-utils-0.26.5-38.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-3.28.2-8.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-browser-plugin-3.28.2-8.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-devel-3.28.2-8.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-dvi-3.28.2-8.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-libs-3.28.2-8.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-nautilus-3.28.2-8.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'okular-4.10.5-7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'okular-devel-4.10.5-7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'okular-libs-4.10.5-7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'okular-part-4.10.5-7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-0.26.5-38.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-cpp-0.26.5-38.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-cpp-devel-0.26.5-38.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-demos-0.26.5-38.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-devel-0.26.5-38.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-glib-0.26.5-38.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-glib-devel-0.26.5-38.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-qt-0.26.5-38.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-qt-devel-0.26.5-38.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-utils-0.26.5-38.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'evince / evince-browser-plugin / evince-devel / etc');
}
