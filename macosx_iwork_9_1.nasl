#TRUSTED 5dc1ed495adc517a05c564e262a802b720fad5bebc2657b164cf815e67ca5a0932547e6e159508ec307b0c77d7e1a8f6b104df960e0be968098009a77320f40d7374579b85416f2c9e1efba0ca13a0f10db2044bf19345542f1ff9cdaad6354b221d299a182af5a6f81b5ee02a322ed2dd5d49b0b1290c5e6d8a0994b46fad7ff57ae1e7ec6a13cfe4412a3c143196d5c04547bf3557deb14781a9a0bdc0abf882e6476f1657cc5279578e5a76f2b63752a7ec6f9b29a65289a7c52a3e8f224ef2498853aaffd75aee3608f9cdc1b110d011357199552e7f34eb3ec2d8cd73aca2c930a26c1fcbb2a602ac522d36b1744f1f508c114de92ab450460e7ab82c8b4bd4365d8b56a464c9f10b1d4f65156e3d0d3c32c753b1bfb2446ef9ae62db89551319f00f4b4a9295bc655b18aff9ea68160d231471bcd87d664196d08238d183075332e8ad9385b878ba7adf7fd3ff0711781a5bf9d824a9898278918a9d82a66bd67143315585f3b5bf9662454d19a88b70e7ed34f74e4ae4425ce030bebac35e5205d517bdd5602fbcadc4e234c0d2d664a3db943a706d577e52366102b6d7adeac5850b260d09dd627c220f7b69cc4ecc5a9ec608886255fac4bac45ca1f5ac6342cde08ad007d2e643eb91dfe681c6c6e5edcf2b28bcae0e98e72bdc18cbd5516b91ed0272166bab742d458b42be15505fbb5b7392192d17fb42cdf982
#TRUST-RSA-SHA256 a45392b3c6bfec9f203f74af4a651debdb18359f20fd537dda9c5d6a5812c9a3ab7dc6ee6e9940f466311471d10d50e0cdc4ee7a8ba201457db0adeab9c97caff11f9e677a505fed1202f60cf8a3195b996cb24f50503c50efaa6a4bbf3043ac7895a05bf341d899b563ba636452d9fdd2d2d96ac3a2b2f8e49a7a7d1ef876893dd1566c2e379d59bbfbb3455076d79961ec9c8cebf8d71a20d83c9e06b02075506c54c9a9138320326538eca14b96c1d7042bab071ceb6d7f25d4f34f213ce661192cb5b647c2f7768325ba42f7e2928b2c93023e64a0f168c6266f110d8cf7e2bec83b0d7e4ab165d4d85f716fc55161ebdf46c83f8498762a22ec2bd0a5bdd92f8b78f5201f557113b210c26c41aae95af683c30a1e24a52e1f90e4517c1f2d6d8b5f05566737513fc5af595293c21a9a5443e68aabb93a1187fa3ce6d8225a7ecf0db6ba5b84a29ae86979d480a303a56d5ede05f0fb6702b2a3887558f40b9299304303665264a9e9bf25818438909f9318219fecafc8ace88e18ce6def6bf2e869aee17ae21f6e5f7311bbf2f118535008435b85b6d265a634ee9673877d8e14274400552685177ec948c1bdbb5ede7f5c9398330d034a62a37c8c154f3e1c101e3d5b295374ff56c4f1e2ec8633fda497ae7dd781bd7c1ac0eb1345a1ead8b7e768dddc73b34c6991a2c1517cc32f451c51728da17e6a493785d18fde
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(55693);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2010-3785", "CVE-2010-3786", "CVE-2011-1417");
  script_bugtraq_id(44799, 44812, 46832);

  script_name(english:"Mac OS X : iWork 9.x < 9.1 Multiple Vulnerabilities");
  script_summary(english:"Check the installed version of Numbers");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an office suite that is affected by several vulnerabilities.");

  script_set_attribute(
    attribute:"description",
    value:
"The version of iWork 9.x installed on the remote Mac OS X host is earlier than 9.1. As such, it is potentially
affected by several vulnerabilities :

  - A buffer overflow in iWork's handling of Excel files in
    Numbers may lead to an application crash or arbitrary 
    code execution. (CVE-2010-3785)

  - A memory corruption issue in iWork's handling of Excel 
    files in Numbers may lead to an application crash or 
    arbitrary code execution. (CVE-2010-3786)

  - A memory corruption issue in iWork's handling of 
    Microsoft Word files in Pages may lead to an 
    application crash or arbitrary code execution.
    (CVE-2011-1417)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4830");
  # http://lists.apple.com/archives/security-announce/2011/Jul/msg00003.html 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84d8e8f6");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518976/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Apply the iWork 9.1 Update and verify the installed version of Numbers is 2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3785");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages", "Host/MacOSX/packages/boms");

  exit(0);
}


include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');
include('macosx_func.inc');



enable_ssh_wrappers();

if (!get_kb_item('Host/local_checks_enabled')) exit(0, 'Local checks are not enabled.');


os = get_kb_item('Host/MacOSX/Version');
if (!os) exit(0, 'The host does not appear to be running Mac OS X.');


# Check list of package to ensure that iWork 9.x is installed.
boms = get_kb_item('Host/MacOSX/packages/boms');
packages = get_kb_item('Host/MacOSX/packages');
if (boms)
{
  if ('pkg.iWork09' >!< boms) exit(0, 'iWork 9.x is not installed.');
}
# nb: iWork up to 9.0.5 is available for 10.4 so we need to be sure we
#     identify installs of that. The 9.1 Update does not, though, work on it.
else if (packages)
{
  if (!egrep(pattern:"^iWork ?09", string:packages)) exit(0, 'iWork 9.x is not installed.');
}
if (!boms && !packages) exit(1, 'Failed to list installed packages / boms.');


# Check for the update or a later one.
if (
  boms &&
  egrep(pattern:"^com\.apple\.pkg\.iWork_9[1-9][0-9]*_Update", string:boms)
) exit(0, 'The host has the iWork 9.1 Update or later installed and therefore is not affected.');


# Let's make sure the version of the Numbers app indicates it's affected.
path = '/Applications/iWork \'09/Numbers.app';
plist = path + '/Contents/Info.plist';
cmd =  'cat "' + plist + '" | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(1, 'Failed to get the version of Numbers.');

version = chomp(version);
if (version !~ "^[0-9]+\.") exit(1, 'The Numbers version does not appear to be numeric (' +version+').');

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 2 && ver[1] < 1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path                         : ' + path + 
      '\n  Installed version of Numbers : ' + version + 
      '\n  Fixed version of Numbers     : 2.1\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else exit(0, 'The host is not affected since Numbers ' + version + ' is installed.');
