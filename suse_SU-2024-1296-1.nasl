#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1296-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(193354);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/20");

  script_cve_id("CVE-2023-46048");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1296-1");

  script_name(english:"SUSE SLES12 Security Update : texlive (SUSE-SU-2024:1296-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by a vulnerability as referenced
in the SUSE-SU-2024:1296-1 advisory.

  - Tex Live 944e257 has a NULL pointer dereference in texk/web2c/pdftexdir/writet1.c. NOTE: this is disputed
    because it should be categorized as a usability problem. (CVE-2023-46048)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222126");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/034982.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-46048");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46048");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libkpathsea6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libptexenc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bibtex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-checkcites-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-context-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cweb-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dviasm-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvidvi-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dviljk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvipdfmx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvipng-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvips-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvisvgm-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-gsftopk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-jadetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-kpathsea-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-kpathsea-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lacheck-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latex-bin-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lua2dox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-luaotfload-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-luatex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-makeindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-metafont-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-metapost-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mfware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mptopdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdftex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pstools-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ptexenc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-seetexk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-splitindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tex4ht-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texconfig-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-thumbpdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-vlna-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-web-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xdvi-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xmltex-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'reference':'libkpathsea6-6.2.0dev-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libptexenc1-1.3.2dev-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-2013.20130620-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-bibtex-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-bin-devel-2013.20130620-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-checkcites-bin-2013.20130620.svn25623-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-context-bin-2013.20130620.svn29741-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-cweb-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-dviasm-bin-2013.20130620.svn8329-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-dvidvi-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-dviljk-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-dvipdfmx-bin-2013.20130620.svn30845-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-dvipng-bin-2013.20130620.svn30845-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-dvips-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-dvisvgm-bin-2013.20130620.svn30613-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-gsftopk-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-jadetex-bin-2013.20130620.svn3006-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-kpathsea-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-kpathsea-devel-6.2.0dev-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-lacheck-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-latex-bin-bin-2013.20130620.svn14050-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-lua2dox-bin-2013.20130620.svn29053-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-luaotfload-bin-2013.20130620.svn30313-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-luatex-bin-2013.20130620.svn30845-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-makeindex-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-metafont-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-metapost-bin-2013.20130620.svn30845-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-mfware-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-mptopdf-bin-2013.20130620.svn18674-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-pdftex-bin-2013.20130620.svn30845-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-pstools-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-ptexenc-devel-1.3.2dev-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-seetexk-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-splitindex-bin-2013.20130620.svn29688-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-tetex-bin-2013.20130620.svn29741-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-tex-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-tex4ht-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-texconfig-bin-2013.20130620.svn29741-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-thumbpdf-bin-2013.20130620.svn6898-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-vlna-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-web-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-xdvi-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-xetex-bin-2013.20130620.svn30845-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'texlive-xmltex-bin-2013.20130620.svn3006-22.11.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libptexenc1-1.3.2dev-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-2013.20130620-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-bibtex-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-bin-devel-2013.20130620-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-checkcites-bin-2013.20130620.svn25623-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-context-bin-2013.20130620.svn29741-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-cweb-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-dviasm-bin-2013.20130620.svn8329-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-dvidvi-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-dviljk-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-dvipdfmx-bin-2013.20130620.svn30845-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-dvipng-bin-2013.20130620.svn30845-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-dvips-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-dvisvgm-bin-2013.20130620.svn30613-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-gsftopk-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-jadetex-bin-2013.20130620.svn3006-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-kpathsea-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-kpathsea-devel-6.2.0dev-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-lacheck-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-latex-bin-bin-2013.20130620.svn14050-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-lua2dox-bin-2013.20130620.svn29053-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-luaotfload-bin-2013.20130620.svn30313-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-luatex-bin-2013.20130620.svn30845-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-makeindex-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-metafont-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-metapost-bin-2013.20130620.svn30845-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-mfware-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-mptopdf-bin-2013.20130620.svn18674-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-pdftex-bin-2013.20130620.svn30845-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-pstools-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-ptexenc-devel-1.3.2dev-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-seetexk-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-splitindex-bin-2013.20130620.svn29688-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-tetex-bin-2013.20130620.svn29741-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-tex-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-tex4ht-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-texconfig-bin-2013.20130620.svn29741-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-thumbpdf-bin-2013.20130620.svn6898-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-vlna-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-web-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-xdvi-bin-2013.20130620.svn30088-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-xetex-bin-2013.20130620.svn30845-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'texlive-xmltex-bin-2013.20130620.svn3006-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libkpathsea6-6.2.0dev-22.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libkpathsea6 / libptexenc1 / texlive / texlive-bibtex-bin / etc');
}
