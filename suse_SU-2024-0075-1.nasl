#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0075-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(187939);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/11");

  script_cve_id("CVE-2023-0950", "CVE-2023-2255");
  script_xref(name:"IAVB", value:"2023-B-0037-S");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0075-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : LibreOffice (SUSE-SU-2024:0075-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2024:0075-1 advisory.

  - Improper Validation of Array Index vulnerability in the spreadsheet component of The Document Foundation
    LibreOffice allows an attacker to craft a spreadsheet document that will cause an array index underflow
    when loaded. In the affected versions of LibreOffice certain malformed spreadsheet formulas, such as
    AGGREGATE, could be created with less parameters passed to the formula interpreter than it expected,
    leading to an array index underflow, in which case there is a risk that arbitrary code could be executed.
    This issue affects: The Document Foundation LibreOffice 7.4 versions prior to 7.4.6; 7.5 versions prior to
    7.5.1. (CVE-2023-0950)

  - Improper access control in editor components of The Document Foundation LibreOffice allowed an attacker to
    craft a document that would cause external links to be loaded without prompt. In the affected versions of
    LibreOffice documents that used floating frames linked to external files, would load the contents of
    those frames without prompting the user for permission to do so. This was inconsistent with the treatment
    of other linked content in LibreOffice. This issue affects: The Document Foundation LibreOffice 7.4
    versions prior to 7.4.7; 7.5 versions prior to 7.5.3. (CVE-2023-2255)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211746");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-January/017614.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1eb8062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2255");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0950");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:atk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:atk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:atk-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dragonbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:fixmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatk-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatk-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-0_3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-icon-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxmlsec1-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxmlsec1-gcrypt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxmlsec1-gnutls1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxmlsec1-nss1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxmlsec1-openssl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Atk-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xmlsec1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xmlsec1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xmlsec1-gcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xmlsec1-gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xmlsec1-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xmlsec1-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED12|SLED_SAP12|SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'atk-devel-2.28.1-6.5.23', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'atk-doc-2.28.1-6.5.23', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'atk-lang-2.28.1-6.5.23', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'dragonbox-devel-1.1.3-8.3.48', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'dragonbox-devel-1.1.3-8.3.48', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'fixmath-devel-2022.07.20-8.3.48', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'fixmath-devel-2022.07.20-8.3.48', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libatk-1_0-0-2.28.1-6.5.23', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libatk-1_0-0-32bit-2.28.1-6.5.23', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libmwaw-0_3-3-0.3.21-7.24.14', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libmwaw-0_3-3-0.3.21-7.24.14', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libmwaw-0_3-3-0.3.21-7.24.14', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libmwaw-devel-0.3.21-7.24.14', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libmwaw-devel-doc-0.3.21-7.24.14', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-base-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-base-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-base-drivers-postgresql-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-base-drivers-postgresql-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-branding-upstream-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-branding-upstream-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-calc-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-calc-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-calc-extensions-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-calc-extensions-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-draw-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-draw-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-filters-optional-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-filters-optional-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-gnome-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-gnome-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-gtk3-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-gtk3-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-icon-themes-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-icon-themes-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-impress-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-impress-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-af-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-af-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-ar-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-ar-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-bg-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-bg-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-ca-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-ca-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-cs-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-cs-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-da-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-da-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-de-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-de-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-en-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-en-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-es-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-es-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-fi-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-fi-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-fr-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-fr-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-gu-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-gu-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-hi-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-hi-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-hr-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-hr-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-hu-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-hu-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-it-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-it-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-ja-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-ja-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-ko-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-ko-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-lt-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-lt-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-nb-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-nb-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-nl-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-nl-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-nn-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-nn-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-pl-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-pl-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-pt_BR-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-pt_BR-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-pt_PT-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-pt_PT-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-ro-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-ro-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-ru-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-ru-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-sk-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-sk-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-sv-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-sv-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-uk-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-uk-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-xh-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-xh-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-zh_CN-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-zh_CN-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-zh_TW-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-zh_TW-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-zu-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-l10n-zu-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-librelogo-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-librelogo-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-mailmerge-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-mailmerge-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-math-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-math-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-officebean-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-officebean-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-pyuno-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-pyuno-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-sdk-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-writer-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-writer-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-writer-extensions-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libreoffice-writer-extensions-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libxmlsec1-1-1.2.37-8.6.21', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libxmlsec1-gcrypt1-1.2.37-8.6.21', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libxmlsec1-gnutls1-1.2.37-8.6.21', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libxmlsec1-nss1-1.2.37-8.6.21', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libxmlsec1-openssl1-1.2.37-8.6.21', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'typelib-1_0-Atk-1_0-2.28.1-6.5.23', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'xmlsec1-1.2.37-8.6.21', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'xmlsec1-devel-1.2.37-8.6.21', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'xmlsec1-gcrypt-devel-1.2.37-8.6.21', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'xmlsec1-gnutls-devel-1.2.37-8.6.21', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'xmlsec1-nss-devel-1.2.37-8.6.21', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'xmlsec1-openssl-devel-1.2.37-8.6.21', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'atk-devel-2.28.1-6.5.23', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libmwaw-0_3-3-0.3.21-7.24.14', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libmwaw-devel-0.3.21-7.24.14', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libmwaw-devel-doc-0.3.21-7.24.14', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-sdk-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'xmlsec1-1.2.37-8.6.21', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'xmlsec1-devel-1.2.37-8.6.21', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'xmlsec1-gcrypt-devel-1.2.37-8.6.21', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'xmlsec1-gnutls-devel-1.2.37-8.6.21', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'xmlsec1-nss-devel-1.2.37-8.6.21', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'xmlsec1-openssl-devel-1.2.37-8.6.21', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'dragonbox-devel-1.1.3-8.3.48', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'dragonbox-devel-1.1.3-8.3.48', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'fixmath-devel-2022.07.20-8.3.48', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'fixmath-devel-2022.07.20-8.3.48', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libmwaw-0_3-3-0.3.21-7.24.14', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libmwaw-0_3-3-0.3.21-7.24.14', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-base-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-base-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-base-drivers-postgresql-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-base-drivers-postgresql-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-branding-upstream-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-branding-upstream-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-calc-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-calc-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-calc-extensions-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-calc-extensions-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-draw-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-draw-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-filters-optional-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-filters-optional-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-gnome-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-gnome-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-gtk3-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-gtk3-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-icon-themes-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-icon-themes-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-impress-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-impress-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-af-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-af-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-ar-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-ar-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-bg-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-bg-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-ca-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-ca-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-cs-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-cs-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-da-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-da-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-de-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-de-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-en-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-en-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-es-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-es-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-fi-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-fi-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-fr-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-fr-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-gu-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-gu-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-hi-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-hi-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-hr-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-hr-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-hu-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-hu-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-it-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-it-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-ja-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-ja-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-ko-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-ko-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-lt-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-lt-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-nb-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-nb-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-nl-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-nl-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-nn-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-nn-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-pl-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-pl-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-pt_BR-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-pt_BR-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-pt_PT-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-pt_PT-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-ro-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-ro-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-ru-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-ru-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-sk-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-sk-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-sv-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-sv-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-uk-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-uk-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-xh-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-xh-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-zh_CN-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-zh_CN-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-zh_TW-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-zh_TW-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-zu-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-l10n-zu-7.5.4.1-48.44.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-librelogo-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-librelogo-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-mailmerge-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-mailmerge-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-math-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-math-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-officebean-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-officebean-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-pyuno-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-pyuno-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-writer-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-writer-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-writer-extensions-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libreoffice-writer-extensions-7.5.4.1-48.44.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'atk-doc-2.28.1-6.5.23', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'atk-lang-2.28.1-6.5.23', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libatk-1_0-0-2.28.1-6.5.23', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libatk-1_0-0-32bit-2.28.1-6.5.23', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libxmlsec1-1-1.2.37-8.6.21', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libxmlsec1-gcrypt1-1.2.37-8.6.21', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libxmlsec1-gnutls1-1.2.37-8.6.21', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libxmlsec1-nss1-1.2.37-8.6.21', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libxmlsec1-openssl1-1.2.37-8.6.21', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'typelib-1_0-Atk-1_0-2.28.1-6.5.23', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'atk-devel / atk-doc / atk-lang / dragonbox-devel / fixmath-devel / etc');
}
