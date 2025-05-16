#TRUSTED 76a5f526fcc2485c89b235d549fb9789ea2be48628af8c5da7dc09f22add33cff79f01302583267edb591bd7c33c419e0d4950bd52dc484e3d717520bb0205560b5dae5660bf1515f08495dc62a395cac547da141b6aa15d4b9ae50856150b47b91c780ade8cb24bcebb7049215409a4bd1a277f1ac3b73368b8672430a0d4e8619d213b5650f94bfa252555f4578185d5a1779b597dda976ce1051080bc0b72477da0330e385f6130992ff1e7ae469ae284fe624acff4786e60ab4ef505a216a7d261e471d39990c4cb4e3cd5d605b98e2a5a7ad6401c56d02039f7252466b75559cd0781fa3ce7e19ff99e761070c6f32209b251d8fe67868ab406fd120e7841c4b79bdfd49ca9ed48532eb33570d9e8bc0f946e0c722439c4993015a9b7e5aef83e94ef5cbbac6d50575c177eb64c63ce7c89a8c99b1dba4e7b4b4bf4c76e334db4151e87c468720cd51e83fa3ba688038f7c0d26911533c84187163bbea67df2e3f5ee269c4a5ba7802d642fa161186ff95103b25c8dde006e30367507cfe316d796957e512444088ad37036eff652d9b696e16c4f7f97778f41af89889e538d6c5bfa2ac0db8881349d329240df909f0149193d4bfbee95a2bb24b5eb4a3f6b6421a9d5e6f4c30d46cb3b65ae87007d1fd9da89cdc2b5a87ddac2798ea59982b2c3c3c8102863bfe0d13f3828343bdf286dee562954e3523745d2871c80
#TRUST-RSA-SHA256 b0bf140f113056525419de2e8e7d44074b87382da9735952d4195015e7705a075dce7859e4240b3063c24e0cdd5e21a8492e7c81da55d4b8c8983ff9ba3abe98f0443e1b43cf83db7333e7487411d0c7c89b9eb1f78d51d9b0f4779432b6abe82344014771deb06cac87eeb7b260cfede385a5f0f73d4cb8c1230f663edf1975be4d99734c8e65b903036de6a2ce7012d14e22910f5f88e738a2d2c920a20cfbede575e02f497e013aa935fd202bc7ad2662dce2764f4668db708cd92f388bb54e35c1a99898f91d0439e0a30cb4ff4544240f85f71e34b8afff5f116ffbe843db7dc64de5f976a058c7cac2a4ebfc65acda1b2afdb5af68fa4a9159a0bad1a8b8e084fdead25728655d0cffc388aa5a310e3be46b98c6391671828d129d25f4b8f47c085e4fb846835c490a38623d6331765a40e09418732ffa652d45361daeee649896492485440db9adc07cbeea879caa4e7625f79e956b86a1175e0613b017804cf1ba96d0a90c19d72625c70ff306801e9937b026e971481f621f4a939fdc5508f1748f0edac31c871aad116c4825e7660a32ad34b1419cddf514ab9dcac4f880bfd04123fae4d757a9a595139f38fa5bbf7857666b05c5928ad8d39ac18e04d17625005eebaf98253d1f10f5962633c3444e4151c331616fe69c24ce3f67a08dfdf7106af9ffec34e20b77bb13384ddbc8d88a08422a123e170786edc7
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(61998);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2012-0547");
  script_bugtraq_id(55339);

  script_name(english:"Mac OS X : Java for OS X 2012-005");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that contains methods that can
aid in further attacks.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7 or 10.8 host is running a version of Java
for Mac OS X that is missing update 2012-005, which updates the Java
version to 1.6.0_35.  As such, it potentially contains two methods
that do not properly restrict access to information about other
classes.  Specifically, the 'getField' and 'getMethod' methods in the
'sun.awt.SunToolkit' class provided by the bundled SunToolKit can be
used to obtain any field or method of a class - even private fields
and methods. 

Please note this issue is not directly exploitable, rather it can aid
in attacks against other, directly exploitable vulnerabilities, such
as that found in CVE-2012-4681.");
  # http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00370937");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5473");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524112/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Apply the Java for OS X 2012-005 update, which includes version 14.4.0
of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0547");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.[78]([^0-9]|$)", string:os)) 
  audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8");

cmd = 'ls /System/Library/Java';
results = exec_cmd(cmd:cmd);
if (isnull(results)) exit(1, "Unable to determine if the Java runtime is installed.");

if ('JavaVirtualMachines' >!< results) audit(AUDIT_NOT_INST, "Java for OS X");


plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd = 
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

fixed_version = "14.4.0";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
