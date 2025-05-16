#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0183. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51827);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id(
    "CVE-2010-3450",
    "CVE-2010-3451",
    "CVE-2010-3452",
    "CVE-2010-3453",
    "CVE-2010-3454",
    "CVE-2010-3689",
    "CVE-2010-4253",
    "CVE-2010-4643"
  );
  script_xref(name:"RHSA", value:"2011:0183");

  script_name(english:"RHEL 6 : openoffice.org (RHSA-2011:0183)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for openoffice.org.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2011:0183 advisory.

    OpenOffice.org is an office productivity suite that includes desktop
    applications, such as a word processor, spreadsheet application,
    presentation manager, formula editor, and a drawing program.

    An array index error and an integer signedness error were found in the way
    OpenOffice.org parsed certain Rich Text Format (RTF) files. An attacker
    could use these flaws to create a specially-crafted RTF file that, when
    opened, would cause OpenOffice.org to crash or, possibly, execute arbitrary
    code with the privileges of the user running OpenOffice.org.
    (CVE-2010-3451, CVE-2010-3452)

    A heap-based buffer overflow flaw and an array index error were found in
    the way OpenOffice.org parsed certain Microsoft Office Word documents. An
    attacker could use these flaws to create a specially-crafted Microsoft
    Office Word document that, when opened, would cause OpenOffice.org to crash
    or, possibly, execute arbitrary code with the privileges of the user
    running OpenOffice.org. (CVE-2010-3453, CVE-2010-3454)

    A heap-based buffer overflow flaw was found in the way OpenOffice.org
    parsed certain Microsoft Office PowerPoint files. An attacker could use
    this flaw to create a specially-crafted Microsoft Office PowerPoint file
    that, when opened, would cause OpenOffice.org to crash or, possibly,
    execute arbitrary code with the privileges of the user running
    OpenOffice.org. (CVE-2010-4253)

    A heap-based buffer overflow flaw was found in the way OpenOffice.org
    parsed certain TARGA (Truevision TGA) files. An attacker could use this
    flaw to create a specially-crafted TARGA file. If a document containing
    this specially-crafted TARGA file was opened, or if a user tried to insert
    the file into an existing document, it would cause OpenOffice.org to crash
    or, possibly, execute arbitrary code with the privileges of the user
    running OpenOffice.org. (CVE-2010-4643)

    A directory traversal flaw was found in the way OpenOffice.org handled the
    installation of XSLT filter descriptions packaged in Java Archive (JAR)
    files, as well as the installation of OpenOffice.org Extension (.oxt)
    files. An attacker could use these flaws to create a specially-crafted XSLT
    filter description or extension file that, when opened, would cause the
    OpenOffice.org Extension Manager to modify files accessible to the user
    installing the JAR or extension file. (CVE-2010-3450)

    A flaw was found in the script that launches OpenOffice.org. In some
    situations, a . character could be included in the LD_LIBRARY_PATH
    variable, allowing a local attacker to execute arbitrary code with the
    privileges of the user running OpenOffice.org, if that user ran
    OpenOffice.org from within an attacker-controlled directory.
    (CVE-2010-3689)

    Red Hat would like to thank OpenOffice.org for reporting the CVE-2010-3451,
    CVE-2010-3452, CVE-2010-3453, CVE-2010-3454, and CVE-2010-4643 issues; and
    Dmitri Gribenko for reporting the CVE-2010-3689 issue. Upstream
    acknowledges Dan Rosenberg of Virtual Security Research as the original
    reporter of the CVE-2010-3451, CVE-2010-3452, CVE-2010-3453, and
    CVE-2010-3454 issues.

    This update also fixes the following bug:

    * OpenOffice.org did not create a lock file when opening a file that was on
    a share mounted via SFTP. Additionally, if there was a lock file, it was
    ignored. This could result in data loss if a file in this situation was
    opened simultaneously by another user. (BZ#671087)

    All OpenOffice.org users are advised to upgrade to these updated packages,
    which contain backported patches to correct these issues. All running
    instances of OpenOffice.org applications must be restarted for this update
    to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2011/rhsa-2011_0183.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8270b0bd");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=602324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=641224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=641282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=658259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=667588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=671087");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2011:0183");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL openoffice.org package based on the guidance in RHSA-2011:0183.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4643");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-3689");
  script_cwe_id(122);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-brand");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-base-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-brand");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-calc-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-draw-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-impress-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-as_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-cy_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-eu_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-fi_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ja_JP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-kn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ko_KR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-mai_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ml_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-mr_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nr_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nso_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-or_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ss_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-st_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-te_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-tn_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ts_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ve_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-xh_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-math-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-presentation-minimizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-presenter-screen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-report-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-writer-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/i386/debug',
      'content/dist/rhel/client/6/6Client/i386/optional/debug',
      'content/dist/rhel/client/6/6Client/i386/optional/os',
      'content/dist/rhel/client/6/6Client/i386/optional/source/SRPMS',
      'content/dist/rhel/client/6/6Client/i386/os',
      'content/dist/rhel/client/6/6Client/i386/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/debug',
      'content/dist/rhel/client/6/6Client/x86_64/optional/debug',
      'content/dist/rhel/client/6/6Client/x86_64/optional/os',
      'content/dist/rhel/client/6/6Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/os',
      'content/dist/rhel/client/6/6Client/x86_64/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/debug',
      'content/dist/rhel/power/6/6Server/ppc64/optional/debug',
      'content/dist/rhel/power/6/6Server/ppc64/optional/os',
      'content/dist/rhel/power/6/6Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/os',
      'content/dist/rhel/power/6/6Server/ppc64/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/os',
      'content/dist/rhel/server/6/6Server/i386/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/optional/debug',
      'content/dist/rhel/server/6/6Server/i386/optional/os',
      'content/dist/rhel/server/6/6Server/i386/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/os',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/optional/debug',
      'content/dist/rhel/server/6/6Server/x86_64/optional/os',
      'content/dist/rhel/server/6/6Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/os',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/os',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/os',
      'content/dist/rhel/system-z/6/6Server/s390x/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/source/SRPMS',
      'content/fastrack/rhel/client/6/i386/debug',
      'content/fastrack/rhel/client/6/i386/optional/debug',
      'content/fastrack/rhel/client/6/i386/optional/os',
      'content/fastrack/rhel/client/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/client/6/i386/os',
      'content/fastrack/rhel/client/6/i386/source/SRPMS',
      'content/fastrack/rhel/client/6/x86_64/debug',
      'content/fastrack/rhel/client/6/x86_64/optional/debug',
      'content/fastrack/rhel/client/6/x86_64/optional/os',
      'content/fastrack/rhel/client/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/6/x86_64/os',
      'content/fastrack/rhel/client/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/6/ppc64/debug',
      'content/fastrack/rhel/power/6/ppc64/optional/debug',
      'content/fastrack/rhel/power/6/ppc64/optional/os',
      'content/fastrack/rhel/power/6/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/6/ppc64/os',
      'content/fastrack/rhel/power/6/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/os',
      'content/fastrack/rhel/server/6/i386/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/loadbalancer/debug',
      'content/fastrack/rhel/server/6/i386/loadbalancer/os',
      'content/fastrack/rhel/server/6/i386/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/optional/debug',
      'content/fastrack/rhel/server/6/i386/optional/os',
      'content/fastrack/rhel/server/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/debug',
      'content/fastrack/rhel/server/6/i386/resilientstorage/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/os',
      'content/fastrack/rhel/server/6/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/debug',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/os',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/optional/debug',
      'content/fastrack/rhel/server/6/x86_64/optional/os',
      'content/fastrack/rhel/server/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/6/s390x/debug',
      'content/fastrack/rhel/system-z/6/s390x/optional/debug',
      'content/fastrack/rhel/system-z/6/s390x/optional/os',
      'content/fastrack/rhel/system-z/6/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/6/s390x/os',
      'content/fastrack/rhel/system-z/6/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/6/i386/debug',
      'content/fastrack/rhel/workstation/6/i386/optional/debug',
      'content/fastrack/rhel/workstation/6/i386/optional/os',
      'content/fastrack/rhel/workstation/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/6/i386/os',
      'content/fastrack/rhel/workstation/6/i386/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/debug',
      'content/fastrack/rhel/workstation/6/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/6/x86_64/optional/os',
      'content/fastrack/rhel/workstation/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/os',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'autocorr-af-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-bg-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-cs-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-da-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-de-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-en-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-es-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-eu-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-fa-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-fi-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-fr-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-ga-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-hu-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-it-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-ja-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-ko-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-lb-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-lt-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-mn-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-nl-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-pl-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-pt-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-ru-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-sk-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-sl-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-sv-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-tr-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-vi-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'autocorr-zh-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-base-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-base-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-base-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-base-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-brand-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-brand-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-brand-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-brand-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-calc-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-calc-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-calc-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-calc-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-draw-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-draw-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-draw-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-draw-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-impress-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-impress-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-impress-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-impress-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-math-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-math-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-math-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-math-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-writer-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-writer-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-writer-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'broffice.org-writer-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-base-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-base-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-base-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-base-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-base-core-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-base-core-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-base-core-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-base-core-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-brand-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-brand-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-brand-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-brand-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-bsh-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-bsh-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-bsh-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-bsh-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-calc-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-calc-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-calc-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-calc-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-calc-core-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-calc-core-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-calc-core-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-calc-core-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-core-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-core-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-core-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-core-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-devel-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-devel-3.2.1-19.6.el6_0.5', 'cpu':'ppc', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-devel-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-devel-3.2.1-19.6.el6_0.5', 'cpu':'s390', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-devel-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-devel-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-draw-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-draw-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-draw-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-draw-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-draw-core-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-draw-core-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-draw-core-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-draw-core-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-emailmerge-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-emailmerge-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-emailmerge-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-emailmerge-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-graphicfilter-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-graphicfilter-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-graphicfilter-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-graphicfilter-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-headless-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-headless-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-headless-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-headless-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-impress-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-impress-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-impress-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-impress-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-impress-core-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-impress-core-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-impress-core-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-impress-core-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-javafilter-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-javafilter-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-javafilter-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-javafilter-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-af_ZA-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-af_ZA-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-af_ZA-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-af_ZA-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ar-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ar-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ar-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ar-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-as_IN-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-as_IN-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-as_IN-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-as_IN-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-bg_BG-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-bg_BG-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-bg_BG-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-bg_BG-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-bn-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-bn-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-bn-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-bn-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ca_ES-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ca_ES-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ca_ES-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ca_ES-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-cs_CZ-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-cs_CZ-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-cs_CZ-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-cs_CZ-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-cy_GB-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-cy_GB-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-cy_GB-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-cy_GB-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-da_DK-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-da_DK-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-da_DK-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-da_DK-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-de-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-de-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-de-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-de-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-dz-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-dz-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-dz-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-dz-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-el_GR-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-el_GR-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-el_GR-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-el_GR-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-en-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-en-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-en-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-en-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-es-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-es-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-es-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-es-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-et_EE-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-et_EE-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-et_EE-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-et_EE-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-eu_ES-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-eu_ES-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-eu_ES-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-eu_ES-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-fi_FI-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-fi_FI-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-fi_FI-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-fi_FI-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-fr-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-fr-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-fr-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-fr-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ga_IE-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ga_IE-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ga_IE-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ga_IE-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-gl_ES-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-gl_ES-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-gl_ES-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-gl_ES-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-gu_IN-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-gu_IN-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-gu_IN-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-gu_IN-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-he_IL-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-he_IL-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-he_IL-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-he_IL-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-hi_IN-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-hi_IN-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-hi_IN-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-hi_IN-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-hr_HR-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-hr_HR-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-hr_HR-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-hr_HR-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-hu_HU-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-hu_HU-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-hu_HU-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-hu_HU-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-it-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-it-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-it-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-it-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ja_JP-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ja_JP-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ja_JP-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ja_JP-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-kn_IN-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-kn_IN-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-kn_IN-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-kn_IN-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ko_KR-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ko_KR-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ko_KR-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ko_KR-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-lt_LT-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-lt_LT-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-lt_LT-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-lt_LT-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-mai_IN-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-mai_IN-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-mai_IN-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-mai_IN-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ml_IN-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ml_IN-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ml_IN-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ml_IN-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-mr_IN-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-mr_IN-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-mr_IN-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-mr_IN-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ms_MY-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ms_MY-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ms_MY-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ms_MY-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nb_NO-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nb_NO-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nb_NO-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nb_NO-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nl-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nl-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nl-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nl-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nn_NO-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nn_NO-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nn_NO-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nn_NO-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nr_ZA-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nr_ZA-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nr_ZA-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nr_ZA-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nso_ZA-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nso_ZA-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nso_ZA-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-nso_ZA-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-or_IN-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-or_IN-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-or_IN-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-or_IN-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pa-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pa-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pa-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pa-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pl_PL-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pl_PL-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pl_PL-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pl_PL-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pt_BR-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pt_BR-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pt_BR-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pt_BR-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pt_PT-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pt_PT-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pt_PT-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-pt_PT-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ro-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ro-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ro-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ro-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ru-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ru-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ru-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ru-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sk_SK-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sk_SK-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sk_SK-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sk_SK-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sl_SI-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sl_SI-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sl_SI-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sl_SI-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sr-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sr-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sr-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sr-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ss_ZA-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ss_ZA-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ss_ZA-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ss_ZA-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-st_ZA-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-st_ZA-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-st_ZA-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-st_ZA-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sv-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sv-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sv-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-sv-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ta_IN-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ta_IN-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ta_IN-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ta_IN-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-te_IN-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-te_IN-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-te_IN-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-te_IN-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-th_TH-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-th_TH-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-th_TH-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-th_TH-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-tn_ZA-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-tn_ZA-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-tn_ZA-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-tn_ZA-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-tr_TR-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-tr_TR-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-tr_TR-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-tr_TR-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ts_ZA-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ts_ZA-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ts_ZA-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ts_ZA-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-uk-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-uk-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-uk-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-uk-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ur-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ur-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ur-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ur-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ve_ZA-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ve_ZA-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ve_ZA-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-ve_ZA-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-xh_ZA-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-xh_ZA-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-xh_ZA-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-xh_ZA-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-zh_CN-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-zh_CN-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-zh_CN-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-zh_CN-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-zh_TW-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-zh_TW-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-zh_TW-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-zh_TW-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-zu_ZA-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-zu_ZA-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-zu_ZA-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-langpack-zu_ZA-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-math-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-math-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-math-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-math-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-math-core-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-math-core-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-math-core-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-math-core-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-ogltrans-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-ogltrans-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-ogltrans-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-ogltrans-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-opensymbol-fonts-3.2.1-19.6.el6_0.5', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-pdfimport-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-pdfimport-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-pdfimport-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-pdfimport-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-presentation-minimizer-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-presentation-minimizer-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-presentation-minimizer-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-presentation-minimizer-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-presenter-screen-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-presenter-screen-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-presenter-screen-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-presenter-screen-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-pyuno-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-pyuno-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-pyuno-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-pyuno-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-report-builder-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-report-builder-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-report-builder-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-report-builder-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-rhino-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-rhino-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-rhino-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-rhino-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-sdk-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-sdk-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-sdk-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-sdk-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-sdk-doc-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-sdk-doc-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-sdk-doc-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-sdk-doc-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-testtools-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-testtools-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-testtools-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-testtools-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-ure-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-ure-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-ure-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-ure-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-wiki-publisher-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-wiki-publisher-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-wiki-publisher-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-wiki-publisher-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-writer-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-writer-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-writer-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-writer-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-writer-core-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-writer-core-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-writer-core-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-writer-core-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-xsltfilter-3.2.1-19.6.el6_0.5', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-xsltfilter-3.2.1-19.6.el6_0.5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-xsltfilter-3.2.1-19.6.el6_0.5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openoffice.org-xsltfilter-3.2.1-19.6.el6_0.5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
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
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'autocorr-af / autocorr-bg / autocorr-cs / autocorr-da / autocorr-de / etc');
}
