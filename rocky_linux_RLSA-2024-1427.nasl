#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:1427.
##

include('compat.inc');

if (description)
{
  script_id(196959);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2023-6185", "CVE-2023-6186");
  script_xref(name:"RLSA", value:"2024:1427");

  script_name(english:"Rocky Linux 9 : libreoffice (RLSA-2024:1427)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:1427 advisory.

  - Improper Input Validation vulnerability in GStreamer integration of The Document Foundation LibreOffice
    allows an attacker to execute arbitrary GStreamer plugins. In affected versions the filename of the
    embedded video is not sufficiently escaped when passed to GStreamer enabling an attacker to run arbitrary
    gstreamer plugins depending on what plugins are installed on the target system. (CVE-2023-6185)

  - Insufficient macro permission validation of The Document Foundation LibreOffice allows an attacker to
    execute built-in macros without warning. In affected versions LibreOffice supports hyperlinks with macro
    or similar built-in command targets that can be executed when activated without warning the user.
    (CVE-2023-6186)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:1427");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6186");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-vro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-calc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-graphicfilter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-help-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-impress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-ogltrans-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-pdfimport-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-pyuno-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-ure-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-ure-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libreoffice-writer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'autocorr-af-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-bg-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-ca-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-cs-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-da-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-de-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-dsb-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-el-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-en-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-es-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-fa-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-fi-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-fr-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-ga-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-hr-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-hsb-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-hu-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-is-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-it-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-ja-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-ko-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-lb-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-lt-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-mn-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-nl-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-pl-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-pt-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-ro-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-ru-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-sk-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-sl-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-sr-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-sv-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-tr-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-vi-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-vro-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-zh-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-calc-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-calc-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-calc-debuginfo-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-calc-debuginfo-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-core-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-core-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-core-debuginfo-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-core-debuginfo-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-data-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-graphicfilter-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-graphicfilter-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-graphicfilter-debuginfo-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-graphicfilter-debuginfo-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-en-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-en-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-impress-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-impress-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-impress-debuginfo-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-impress-debuginfo-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-en-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-en-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ogltrans-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ogltrans-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ogltrans-debuginfo-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ogltrans-debuginfo-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-opensymbol-fonts-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-pdfimport-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-pdfimport-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-pdfimport-debuginfo-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-pdfimport-debuginfo-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-pyuno-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-pyuno-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-pyuno-debuginfo-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-pyuno-debuginfo-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ure-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ure-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ure-common-7.1.8.1-12.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ure-debuginfo-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ure-debuginfo-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-writer-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-writer-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-writer-debuginfo-7.1.8.1-12.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-writer-debuginfo-7.1.8.1-12.el9_3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'autocorr-af / autocorr-bg / autocorr-ca / autocorr-cs / autocorr-da / etc');
}
