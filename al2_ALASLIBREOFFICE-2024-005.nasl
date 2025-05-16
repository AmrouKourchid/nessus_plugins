#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASLIBREOFFICE-2024-005.
##

include('compat.inc');

if (description)
{
  script_id(210924);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2024-7788");
  script_xref(name:"IAVB", value:"2024-B-0136-S");

  script_name(english:"Amazon Linux 2 : libreoffice (ALASLIBREOFFICE-2024-005)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of libreoffice installed on the remote host is prior to 5.3.6.1-21. It is, therefore, affected by a
vulnerability as referenced in the ALAS2LIBREOFFICE-2024-005 advisory.

    Improper Digital Signature Invalidation  vulnerability in Zip Repair Mode of The Document Foundation
    LibreOffice allows Signature forgery vulnerability in LibreOfficeThis issue affects LibreOffice: from 24.2
    before < 24.2.5. (CVE-2024-7788)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASLIBREOFFICE-2024-005.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-7788.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update libreoffice' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7788");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-gdb-debug-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-help-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-nlpsolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-officebean-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-ure-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreofficekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libreofficekit-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-libreoffice"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'autocorr-af-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-bg-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-ca-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-cs-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-da-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-de-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-en-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-es-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-fa-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-fi-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-fr-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-ga-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-hr-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-hu-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-is-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-it-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-ja-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-ko-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-lb-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-lt-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-mn-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-nl-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-pl-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-pt-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-ro-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-ru-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-sk-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-sl-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-sr-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-sv-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-tr-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-vi-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autocorr-zh-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-base-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-base-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-bsh-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-bsh-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-calc-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-calc-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-core-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-core-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-data-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-debuginfo-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-debuginfo-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-draw-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-draw-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-emailmerge-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-emailmerge-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-filters-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-filters-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-gdb-debug-support-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-gdb-debug-support-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-glade-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-glade-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-graphicfilter-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-graphicfilter-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-gtk2-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-gtk2-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-gtk3-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-gtk3-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ar-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ar-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-bg-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-bg-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-bn-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-bn-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ca-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ca-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-cs-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-cs-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-da-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-da-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-de-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-de-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-dz-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-dz-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-el-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-el-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-es-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-es-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-et-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-et-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-eu-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-eu-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-fr-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-fr-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-gl-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-gl-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-gu-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-gu-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-hi-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-hi-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-hr-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-hr-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-hu-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-hu-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-id-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-id-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-it-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-it-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ja-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ja-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ko-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ko-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-lt-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-lt-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-lv-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-lv-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-nb-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-nb-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-nl-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-nl-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-nn-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-nn-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-pl-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-pl-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-pt-BR-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-pt-BR-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-pt-PT-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-pt-PT-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ro-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ro-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ru-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ru-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-si-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-si-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-sk-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-sk-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-sl-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-sl-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-sv-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-sv-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ta-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-ta-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-tr-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-tr-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-uk-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-uk-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-zh-Hans-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-zh-Hans-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-zh-Hant-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-help-zh-Hant-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-impress-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-impress-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-af-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-af-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ar-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ar-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-as-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-as-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-bg-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-bg-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-bn-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-bn-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-br-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-br-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ca-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ca-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-cs-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-cs-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-cy-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-cy-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-da-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-da-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-de-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-de-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-dz-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-dz-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-el-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-el-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-en-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-en-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-es-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-es-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-et-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-et-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-eu-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-eu-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-fa-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-fa-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-fr-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-fr-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ga-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ga-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-gl-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-gl-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-gu-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-gu-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-hi-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-hi-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-hr-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-hr-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-hu-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-hu-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-id-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-id-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-it-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-it-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ja-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ja-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-kk-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-kk-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-kn-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-kn-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ko-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ko-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-lt-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-lt-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-lv-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-lv-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-mai-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-mai-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ml-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ml-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-mr-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-mr-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-nb-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-nb-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-nl-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-nl-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-nn-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-nn-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-nr-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-nr-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-nso-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-nso-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-or-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-or-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-pa-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-pa-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-pl-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-pl-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-pt-BR-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-pt-BR-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-pt-PT-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-pt-PT-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ro-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ro-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ru-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ru-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-si-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-si-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-sk-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-sk-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-sl-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-sl-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-sr-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-sr-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ss-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ss-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-st-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-st-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-sv-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-sv-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ta-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ta-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-te-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-te-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-th-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-th-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-tn-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-tn-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-tr-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-tr-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ts-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ts-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-uk-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-uk-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ve-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-ve-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-xh-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-xh-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-zh-Hans-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-zh-Hans-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-zh-Hant-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-zh-Hant-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-zu-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-langpack-zu-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-librelogo-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-librelogo-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-math-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-math-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-nlpsolver-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-nlpsolver-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-officebean-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-officebean-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-officebean-common-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-ogltrans-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-ogltrans-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-opensymbol-fonts-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-pdfimport-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-pdfimport-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-postgresql-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-postgresql-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-pyuno-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-pyuno-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-rhino-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-rhino-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-sdk-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-sdk-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-sdk-doc-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-sdk-doc-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-ure-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-ure-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-ure-common-5.3.6.1-21.amzn2.0.8', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-wiki-publisher-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-wiki-publisher-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-writer-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-writer-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-x11-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-x11-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-xsltfilter-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-xsltfilter-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreofficekit-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreofficekit-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreofficekit-devel-5.3.6.1-21.amzn2.0.8', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreofficekit-devel-5.3.6.1-21.amzn2.0.8', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autocorr-af / autocorr-bg / autocorr-ca / etc");
}
