#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_32141. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17558);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");
  script_bugtraq_id(10508);
  script_xref(name:"HP", value:"HPSBUX01113");

  script_name(english:"HP-UX PHSS_32141 : s700_800 11.04 Virtualvault 4.5 IWS Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP-UX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"s700_800 11.04 Virtualvault 4.5 IWS Update : 

Two security vulnerabilities have been reported in Apache HTTP server
(http://httpd.apache.org/) versions prior to Apache 1.3.33 that may
allow a Denial of Service (DoS) attack and execution of arbitrarty
code.");
  script_set_attribute(attribute:"solution", value:
"Install patch PHSS_32141 or subsequent.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"HP-UX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2005-2025 Tenable Network Security, Inc.");

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

if (!hpux_check_ctx(ctx:"11.04"))
{
  exit(0, "The host is not affected since PHSS_32141 applies to a different OS release.");
}

patches = make_list("PHSS_32141", "PHSS_34171", "PHSS_35104", "PHSS_35306", "PHSS_35458", "PHSS_35553");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"VaultTS.VV-CORE-CMN", version:"A.04.50")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS", version:"A.04.50")) flag++;
if (hpux_check_patch(app:"VaultTS.VVOS-ADM-RUN", version:"A.04.50")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
