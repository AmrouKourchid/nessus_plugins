#TRUSTED 2ad9a780b646caba4b1ad9469da1e3af9d5fe24b0a9fe9e0904104b0eded3b3cd6df6134247d20130d79cd0762d1bb9a68d3fb7325f12492a4338e3ccc798ccece29094c7c0b366b0124c1475d41da13bb10b0f407601497e48cc5625cc1fb43213b0ee820903c22dfdd45d3f840a67cdbec4c052f96e09b161baedf2c9dc32274ebfab2a0e38432a5248610320e95de63bebac19c140a8c3344418181bd935410cda962181f9e59199c4f137eb5b59c15333bb5566400fd6e87bdfd5e282c971ebc1476bd5197bff73fe1abc6c32e61167b7dc8f9f3728acf1f8253d74f255ce5e7cc4f2db30445de26d617ee5f034dee1ad9770e9870f569038aa09c04a372770cccb10ddf0a221e02c9ffc75004b9a240da95594e50d34523ec3c8de5fdec65df30386f13b9eb001f877ae7f390bab89fa13fb8e2dea90e5aefde78356bdf6226a302e422f70899827935c14ba02f4371321f8dc3a1170e03e5ca67bff4bd2c8c459d4e4eeb5eb01af8faf45db999811e83f73c3b4684e325903124064e0dd9801a35bc15b215b765f55e338f27fe02fd004d7f5df1db6d6c028769eebae577db0fcdac5e6aa17922c34b401bae0adc667c7b9aad2ca8f95df900cd88d3dbb1e350427a4a56bfcdb5a64102b82343f2b23cc008d62bba38d0b7ee1ae0fa3fee639645e35c06621d9db6b6847fc67a43f18ac2c77ce20f7f95dcc397b95477
#TRUST-RSA-SHA256 1d89bd678bed6d798b8fa44c345ab8a6a4fe7088d911260a2a9ff1f477881b521f3a1bb77b36a9b80da03dc26ef231a2351f91ad622a9b36df981160384dab63473cc02a9257494641f32cb6b2ad7f086c02a1fdd194e434f9c5e8bd8fc576de7b79e6400b5a69a6a7c76455c9f0240185df6c968b11ad881ef34c588406a8f8ef564704fa23739fb6ddc097830d9f8f7a2a1127a092b11e06ed8a5aa2f530f0bc48ca4a03efe4bf75163af5cc23fb082ce70c90798eacb5e8b3630d5bdd2b114daa2fadb36756ade99030d8a75f465784de11a94576f79129e0e00156341d6ae8ae8371aadea864fb9c7ee0b185dd95359d2ded887ca1803a763535c8934eec0799fc9f8fd55f637994f0fddccc3489a3ef9f77097aeee9f45c102381e8e42913edaea7e90ea7299977191f6430c188012966d48de081012f5f0039370ac3a1d025b63f12ebec6419c776cc907851adca6c64fc4eb75bc415003a4dcfcab31c368fd09aba0cb7096131a6954316dbc65aecf7872e49e4cc4bba06f82b7fec343df2da95e39c0a5b67ee1e34db51708bcb026831bdaea96613fae672c1cb26286e76ef209ebf54747512095aec0027c337a44df2622a8cf1ab62de04b970b4f5ad3226779cfe0d52895ffc56a6418c14c5e2c2f7e8c149f0c6366785ed02946214d8f6447156c8e52d687d3c9fbc2f3f3585b05fdb7dbb92aba9a4db7aab8a58
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(54832);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Mac OS X Mac Defender Malware Detection");
  script_summary(english:"Checks for evidence of MacDefender");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Mac OS X host appears to have been compromised."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Using the supplied credentials, Nessus has found evidence that a fake
antivirus software named Mac Defender (alternatively, MacDefender,
MacGuard, MacProtector or MacSecurity) is installed on the remote Mac
OS X host. 

The software is typically installed by means of a phishing scam
targeting Mac users by redirecting them from legitimate websites to
fake ones that tell them their computer is infected with a virus and
then offers this software as a solution. 

Once installed, the malware will perform a 'scan' that falsely
identifies applications such as 'Terminal' or even the shell command
'test' ('[') as infected and will redirect a user's browser to porn
sites in an attempt to trick people into purchasing the software in
order to 'clean up' their system."
  );
  # http://nakedsecurity.sophos.com/2011/05/02/mac-users-hit-with-fake-av-when-using-google-image-search/
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?abf43744"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4650"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Follow the steps in Apple's advisory to remove the malware."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

packages = get_kb_item_or_exit("Host/MacOSX/packages");


apps = make_list(
  "MacDefender",
  "MacGuard",
  "MacSecurity",
  "MacProtector",
  "MacShield"
);

report = '';
foreach app (apps)
{
  # Look for a couple of different indicators.
  info = make_array();

  # - application directory.
  appdir = '/Applications/' + app + '.app';
  cmd1 = 'test -d \'' + appdir + '\' && ls -ld \'' + appdir + '\'';

  # - active process.
  #   nb: this just lists all processes.
  cmd2 = 'ps -axwww -o user,pid,command';

  # - login items.
  #   nb: this just lists all login items.
  cmd3 = '(echo ; /usr/bin/dscl  . -readall /Users NFSHomeDirectory UniqueID) |while read sep; do read Home; read Record; read UniqueID; UniqueID=`echo $UniqueID |awk \'{print $2}\'`; test "$UniqueID" -gt 499 && echo $Record:|awk \'{print $2}\' && Home=`echo $Home|awk \'{print $2}\'` && test -f "$Home"/Library/Preferences/com.apple.loginitems.plist  && /usr/bin/defaults read "$Home"/Library/Preferences/com.apple.loginitems; done';

  results = exec_cmds(cmds:make_list(cmd1, cmd2, cmd3), exit_on_fail:FALSE);
  if(!isnull(results))
  {
    if (strlen(results[cmd1]) >= strlen(app) && app >< results[cmd1])
    {
      info["Application directory"] = appdir;
    }

    if (!strlen(results[cmd2])) exit(1, "Failed to get a list of active processes.");
    else
    {
      matches = egrep(pattern:'('+app+'\\.app/|MacOS\\/'+app+')', string:results[cmd2]);
      if (matches)
      {
        info["Active process"] = join(matches, sep:"");
      }
    }

    if (strlen(results[cmd3]))
    {
      user = "";
      foreach line (split(results[cmd3], keep:FALSE))
      {
        match = pregmatch(pattern:'^/Users/([^:]+):', string:line);
        if (match) user = match[1];

        match = pregmatch(pattern:'^ +Path = "(.+/'+app+'\\.[^"]*)"', string:line);
        if (match && user) info["Login item"] += user + ' (' + match[1] + ')\n';

        if (preg(pattern:'^} *$', string:line)) user = '';
      }
    }

    if (max_index(keys(info)))
    {
      max_item_len = 0;
      foreach item (keys(info))
      {
        if (strlen(item) > max_item_len) max_item_len = strlen(item);
      }

      report += '\n  - ' + app + ' : ';
      foreach item (sort(keys(info)))
      {
        val = info[item];
        val = str_replace(find:'\n', replace:'\n'+crap(data:" ", length:max_item_len+11), string:val);
        val = chomp(val);

        report += '\n      o ' + item + crap(data:" ", length:max_item_len-strlen(item)) + ' : ' + val;
      }
      report += '\n';
    }
  }
}

if (report)
{
  report = data_protection::sanitize_user_paths(report_text:report);
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet') security_hole(port:0, extra:report);
  else security_hole(0);
}
else exit(0, "MacDefender is not installed.");
