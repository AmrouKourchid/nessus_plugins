#TRUSTED 481d512e6f1beeb53f5d346dae1e9e1b2b03b79855f86fc0208dddbe3b2c1d9c554a71f652975185a38279d3a2cace2c535a439fc6ddfa6a54034eda3b00af3b2068dab9b181158892abd4c3cb812184fe7321d89f26b33df4595bba1b24a6f116b1cae5bd2bedc1e179a016cab8b93898cfa25b4c86e36616bf992ce5caa18ec090dcf56937ae8258827e380ebb4b2ecf8f17c9b849a607d98e9cd3b1bb73ee9dfa1fa3459fe9a007675a2b463d8271329b8d552badf7df4a4d6aaf6dd39656adc1f435970d5b877204617c81c06b4d5e7fced78ab90acdef018e86892e93cf8164fece463794ca6b62f4572d1720513dca1e7a2840cb4879d40d95f738dc6dc2ebd2c8fa9bd20674c4337e003d08917bc693215c529c719ed78d2007adcee815cfba815c0baf4b6c6ed74600d47ad18a8ed7194518629c1a758a2a4f4839c823fc3e671f009c923fb8fed9eb1151633c35c586a7d3e9bd9854552e71acdc90b5ee559af5d049230f8b4ca7408e528f422113b6dce107dcf7383322841d52c550da5760756ce2f61cbf7e464662773ac6acf0959890c9753c2f2857bf4cd225ba125164bdaf75dd3946c2ffe6125a53c7d4c2e3cb2a0d5191706e1a40b5ac42569f0cdb4ab38d2c89ae24eb4e028ff7899fb64795b92656ef8643445e606578642af8b293c3a11f0e627318ac9688ca5f2734de2eadf8e6fa8e9749ee049c01
#TRUST-RSA-SHA256 643cdce21ba26167f78db81c88139b92e5ff2f159dbeff6265b60eb2270cb58a9a37436d0f7095978613321dfdd2bf03eca47dbac54ae4d9ab2742aa83b15aa6de11ef06bc683439772e5a36f36be826ad717712a853db029ede3e64aee61d9bb6a52adcc2c0b7ad9dfa3d2a052cb3b56082a8381db3ef62a8a7b55f533c81aad9d461f840117520fb32453281df8973fe10a7ea5c892de61d9fac92624a151b4c571dd91e7165c98d47749e5f62ecf57cac494e1aa43d566de3a2df3969f92ade6a3608df8be1383c2ab7e532555f7daa17856b1d8642eaa7afdb5ab451b84b688ecc2f01543a332f6cf515285d6f8464878987eaf0b5b223e621bc56f55ca75e91bb3ca294e0b9487c48b5ed5a6d2471675add053066d1f47a58060169be05a218d55c273536c81ace8fa87a9727894bdfef7a5140765b93bf66a02ad0bdff06d15d3080431f2385c4f6335aa1cf2d2969817e1ce989db93c7e4473cf8aaa3292b3c6aa6a0f388afd8dc5a55fea13b224409aab24746e5c613272af1d9ac092478935e0e4f2c35606fce7a99327ec3c46ad30c4963907d84e9a50e2043e0bf3b8392a5aaa04572f2c0fbcb93f293bafbdc049d0d107b4fcc4e80c1abcac67e0aefebfc3f8a2d0cffac559ef52577a4f47330085a435d346d36fb6e5b79741efd79f2498a464fdcb97503fdb78f33b6b8f1854cec4652474875d6e52a41410a
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");


if (description)
{
  script_id(40480);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2009-2198");
  script_bugtraq_id(35926);

  script_name(english:"Mac OS X : GarageBand < 5.1");
  script_summary(english:"Checks the version of GarageBand");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of GarageBand that is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X 10.5 host is running a version of GarageBand
older than 5.1.  When such versions are opened, Safari's preferences
are changed from the default setting to accept cookies only for the
sites being visited to always except cookies.  This change may allow
third-parties, in particular advertisers, to track a user's browsing
activity."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3732"
  );
  # http://lists.apple.com/archives/security-announce/2009/Aug/msg00000.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a380234"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to GarageBand 5.1 or later and check that Safari's preferences
are set as desired."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2009-2198");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-2198");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/04");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "KB item 'Host/MacOSX/packages' not found.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "KB item 'Host/uname' not found.");

# Mac OS X 10.5 only.
if (egrep(pattern:"Darwin.* 9\.", string:uname))
{
  cmd = GetBundleVersionCmd(file:"GarageBand.app", path:"/Applications", long:FALSE);

  if (islocalhost()) 
    version = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = info_connect();
    if (!ret) exit(1, "Can't open an SSH connection.");
    version = info_send_cmd(cmd:cmd);
    if (info_t == INFO_SSH)
      ssh_close_connection();
  }
  if (!strlen(version)) exit(1, "Failed to get the version of GarageBand.");
  version = chomp(version);

  ver = split(version, sep:'.', keep:FALSE);
  #Prevent FPs if shell handler errors get mixed into results
  if(int(ver[0]) == 0 && ver[0] != "0") exit(1, "Failed to get the version of GarageBand.");
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 5.1.
  if (
    ver[0] < 5 ||
    (ver[0] == 5 && ver[1] < 1)
  )
  {
    gs_opt = get_kb_item("global_settings/report_verbosity");
    if (gs_opt && gs_opt != 'Quiet')
    {
      report = 
        '\n  Installed version : ' + version + 
        '\n  Fixed version     : 5.1\n';
      security_warning(port:0, extra:report);
    }
    else security_warning(0);
  }
  else exit(0, "The remote host is not affected since GarageBand "+version+" is installed.");
}
