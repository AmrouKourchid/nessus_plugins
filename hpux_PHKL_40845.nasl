#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHKL_40845. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45413);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/31");

  script_cve_id("CVE-2009-1030", "CVE-2010-1030");
  script_xref(name:"HP", value:"emr_na-c02063258");
  script_xref(name:"HP", value:"HPSBUX02514");
  script_xref(name:"HP", value:"SSRT100010");

  script_name(english:"HP-UX PHKL_40845 : HP-UX running AudFilter rules enabled, Local Denial of Service (DoS) (HPSBUX02514 SSRT100010 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.31 audit cumulative patch : 

A potential security vulnerability have been identified with HP-UX
with AudFilter rules enabled. The vulnerability could be exploited
locally to create a Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02063258
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?586f0acc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHKL_40845 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:N/I:N/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1030");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"HP-UX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("hpux.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/HP-UX/version")) audit(AUDIT_OS_NOT, "HP-UX");
if (!get_kb_item("Host/HP-UX/swlist")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (!hpux_check_ctx(ctx:"11.31"))
{
  exit(0, "The host is not affected since PHKL_40845 applies to a different OS release.");
}

var patches = make_list("PHKL_40845", "PHKL_41239", "PHKL_41852", "PHKL_43199", "PHKL_44792", "PHKL_44930");
var patch;
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


var flag = 0;
if (hpux_check_patch(app:"OS-Core.CORE2-KRN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"ProgSupport.C-INC", version:"B.11.31")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_report_v4(port:0, severity: SECURITY_WARNING, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
