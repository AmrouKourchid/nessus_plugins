#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(109071);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2018-2563");

  script_name(english:"Solaris 10 (sparc) : 150377-07");
  script_summary(english:"Check for patch 150377-07");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 150377-07"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle Sun Systems Products
Suite (subcomponent: LDAP Library). Supported versions that are
affected are 10 and 11.3. Difficult to exploit vulnerability allows
low privileged attacker with network access via LDAP to compromise
Solaris. Successful attacks of this vulnerability can result in
unauthorized update, insert or delete access to some of Solaris
accessible data as well as unauthorized read access to a subset of
Solaris accessible data."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/150377-07"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 150377-07 or higher");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2563");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150377");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:150637");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:151307");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

showrev = get_kb_item("Host/Solaris/showrev");
if (empty_or_null(showrev)) audit(AUDIT_OS_NOT, "Solaris");
os_ver = pregmatch(pattern:"Release: (\d+.(\d+))", string:showrev);
if (empty_or_null(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Solaris");
full_ver = os_ver[1];
os_level = os_ver[2];
if (full_ver != "5.10") audit(AUDIT_OS_NOT, "Solaris 10", "Solaris " + os_level);
package_arch = pregmatch(pattern:"Application architecture: (\w+)", string:showrev);
if (empty_or_null(package_arch)) audit(AUDIT_UNKNOWN_ARCH);
package_arch = package_arch[1];
if (package_arch != "sparc") audit(AUDIT_ARCH_NOT, "sparc", package_arch);
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150377-07", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150377-07", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150377-07", obsoleted_by:"", package:"SUNWnisu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;

if (flag) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : solaris_get_report()
  );
} else {
  patch_fix = solaris_patch_fix_get();
  if (!empty_or_null(patch_fix)) audit(AUDIT_PATCH_INSTALLED, patch_fix, "Solaris 10");
  tested = solaris_pkg_tests_get();
  if (!empty_or_null(tested)) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWarc / SUNWcsl / SUNWnisu");
}
