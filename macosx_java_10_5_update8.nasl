#TRUSTED a6d7afa61fbf29ee594aafb698ae1900cd48df13720a1f5d33b5460edfa5b22a9012e9d1d75c72d674aeda927025ac1406b8f742cf0c160bfaa402599d609b02aed13b6b8085e48861f074c721651ac2a5a272fe7189ba9d56934d9ea9af6ede1e2097d51488882a56783d033a90734992b32dc2dd4e3af1b8bdcde54c50d809d6eb430854a1f88b6aa8a98c44bed6fab4af87faeb61228688f0cb1b30eae32d7038d84b55f2a726df24e6525310b08b628e50f7426ce5ee01feba05227c39d3f9223b7063cd94864d12b391680d4226055253b48d3b5b9afbf1ae9d07fad0b1669305aa07dffedf75fa7904d1721b32d3fff50f18e6917784eed5cc2e1a70d786684e34141c846cf1dcf0e141b175f4d6c41e7b1edbde53feb2dfcf3cba0072ea112d382d17da775bf1b14978f032bcf676628f98f233e517c59379ee5a846e30da47617703aa7a1b9c3f40dd7c349f93b4b3ada1b9a5f92c14ffb153625b64cb0b110be7ba5b4032204f2784113ae260091a392670cce0ee97712e3ed8489600ee6fde74040ed8caa485a4aa9e11abfe33a81deb8cefaa07336118badf3bbf2f19148d9930c3427eb6cb774d62eb4c4efa1bf3a3a373d7f927210c8210bf9b5539339ac41e25c8581e2a19858b35d524dc7889a910b8dc75f0ce05aec83b4155371eb278de011846849bf7629ca664e09557e609686af43fbb4e835989cd98
#TRUST-RSA-SHA256 4b0a05f728c17584faffe153c05e73a886f562bcfac3685cbc855317839c440272c9114e2cf4c08bb33c78ef986482f287af39f130571973f09f2ac09ce40c7cfc5170fd233249a176936795a9f5c25ccb23e2de0b0ba6d5dc854c0c187ce15d245b3422ad689e4497621022f2627ba35c2391596b630d2d1df727cd028b0a60cb197cc9357f38f879707b8b1541979842cbd9580bee15b633cb88cbf7183863eaa221b1c874a585d204022225e1b6036a42d54e01d8482c1f6d7c6aeb0305ff8c9c0fea956494bd876674c74a99f73b12b6edac2e5fc3393e2ea08ec8b349d0528d87bb38f1789ffddbb9823fcc4242d95efef01b83365a1d7ec0a0e589b33977ff27807bf8d8325be61f37ac5b457577910ddcf1c4a5e23745c817bb8c371f641909c1d7adc90e4f242d453b4743e709c3f303f95d5f12ee9bf819332f0e28b5dc9252b683647eea0771ce979b2afe7892c23d80a718d472ad4c650b0318884bd46e38a9c3d902f303bb5ca588bde4b3da8771010ec4d3c1235be824cabd82cf1965f0bcfde3cc5a86a9abf188aba991ca5d19f7cf24f019cbb40f4d812ca25c299e9b8db0dd56a2a8f17266948d56627e5be3481dd86a73ad965b9facf872ee8e552ca255bb477c709a0879f56a45c7bfe7bd3d6734bedb89b137f89d88bcd95f612fe973e18a91d25da3de1d5836395210992089520aadd8b356323b5beb
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");


if (description)
{
  script_id(50072);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2010-1321",
    "CVE-2010-1826",
    "CVE-2010-1827"
  );
  script_bugtraq_id(36935, 40235, 44277, 44279);

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 8");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.5 that is missing Update 8.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
or applications to obtain elevated privileges and lead to execution of
arbitrary code with the privileges of the current user outside the
Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4418"
  );
  # http://lists.apple.com/archives/security-announce/2010/Oct/msg00001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6933e9b1"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.5 Update 8 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1321");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


enable_ssh_wrappers();

function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = info_connect();
    if (!ret) exit(1, "info_connect() failed.");
    buf = info_send_cmd(cmd:cmd);
    if (info_t == INFO_SSH)
      ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.5 and thus is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd = 
  'cat ' + plist + ' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 12.7.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 7)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report = 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.7.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
