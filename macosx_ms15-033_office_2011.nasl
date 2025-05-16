#TRUSTED 39d6dde0835faadfc3b1747dfa0d2ffcbafd2502acb0a26c02e45c8b8366f7dee886e62b000e6b1c6fdb2370e74a5c2a0207db66052cfbeb540e76fad09cfe67c9640ec0f04ee6452f00549e368597042fb1ec57418f918fc460e91bb6fb154347d014343212fa802bb8a5c397ae24c7d17a3f71103d753fe0721de864f52efe8c1fbff1e7d070427600e828aa77072104f965c7cf38762685a1da32dd72ed448df3ec48a05055285fd8e6046ed19ae4c94de232586ee0432da5986018cda0967b62ec6c64f4376d0151cdc0d30edb65934efa2fb391b6c3f60ec9abcd574cef2a59b4fc83061fd2b925825228114eae19573300299e4c5fcb8f2ce50d0e7982a58640c5cfadacf0f850ea7e100729e3e0b4bc1ba64e7c47b50af20740c507c20481de101cf60bc49bc060dc45f2ef4db48b50c05b64b4f6339fae4a94ae239bd591a3415cc57c2895996079ef13bc574c3e3843b401ea38ba8304e905ffbf5a4b291bf8f9fe270f2e91d163db3dbdf49db75be08d3f73094c177188396d15e6c0fecf4fe9033f11991c79852ace18d6bdb7b33ffb543940207376941662690682edcb6dcb96816308f43e876bf402bde990c63f5391f53bb9671ba369c623115a21351d8996ee3ad27df2c5d65aa151b523676b04c45329c12b539499204f3a96385d9c5da19540bdb1024a4c21bbf941448cb99fb010f55a53abdbc39d6708
#TRUST-RSA-SHA256 1fa1929a934ac13df45604eceb2c852ee7b202723a5a9392615c781dce8c3c37eabf54e085459f4ca98184e269e89024810f5597ef76331a45616c2bde8d849d381a9175f871fd7a6cd51677612c09b1fc614f2258bd47007d6a14957692acea41b9196d608726ccd0ccade1f9954e9f594e99f46669eed74e201791b02ef027737726c1b6a2ebc7e693822a2f9df2d30036de84ecfe4508c32fb7e57dcaf8f66435f034105e0438f28f1a968936b67c38d2f5ee9de7999f8293ab878ceda26ccc1788ff56571d61035c5e23b56acfe412f12e5cfe0bc44bb32e8ec8287fd7ca0a5544da8493173274ccbdfed43005e15200e9a4f0d53f4c8b8df0a7fa39b3a3ce02bb1da279e7897c710b22239010ad6f14874d28e90257087efdd1a9fecf25b6904bee198f70134e31983e6ae356ab3d1eaef3709c07aff6e982c422b0f11abf68ebc18ae68ae75a3098d85ac55bbaee71cea695fdb104b6cb529b79c7a5ed89a6702e89262b55373ad502b2f453dc254d3dccf8d78dbbd16ea68d03e110f956d1d90564c33a59a4e282401271c2b38b37a685783cf71a44e633957b9703b0e465106e5b27e6b7aa4e893a81e56a80b6fca712eae8c4cb1a6ea86b43d1d2aed50ae1e5a8356d289871b125ec53f810ba59efaac9e5f76f237529cef6c41833bac5106824fa5954ca7b7ad4d3bc03b968aea48fbbb6e0e3ed9c43d684e44ed5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(82767);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2015-1639", "CVE-2015-1641");
  script_bugtraq_id(73991, 73995);
  script_xref(name:"MSFT", value:"MS15-033");
  script_xref(name:"IAVA", value:"2015-A-0090-S");
  script_xref(name:"MSKB", value:"3051737");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"MS15-033: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3048019)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Word installed
that is affected by multiple vulnerabilities :

  - A cross-site scripting vulnerability exists due to
    improper sanitization of HTML strings. A remote attacker
    can exploit this issue by convincing a user to open a
    file or visit a website containing specially crafted
    content, resulting in execution of arbitrary code in the
    context of the current user. (CVE-2015-1639)

  - A remote code execution vulnerability exists due to
    improper handling rich text format files in memory. A
    remote attacker can exploit this vulnerability by
    convincing a user to open a specially crafted file using
    the affected software, resulting in execution of
    arbitrary code in the context of the current user.
    (CVE-2015-1641)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-033");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:outlook_for_mac_for_office_365");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# Gather version info.
info = '';
installs = make_array();

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.4.9';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
}

# Report findings.
if (info)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2011 is not installed.");
  else
  {
    msg = 'The host has ';
    foreach prod (sort(keys(installs)))
      msg += prod + ' ' + installs[prod] + ' and ';
    msg = substr(msg, 0, strlen(msg)-1-strlen(' and '));

    msg += ' installed and thus is not affected.';

    exit(0, msg);
  }
}
