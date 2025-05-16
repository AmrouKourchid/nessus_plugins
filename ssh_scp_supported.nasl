#TRUSTED a36db6873f2d7f2cfca9c4f71707cc839742205112f5f4bf869e84afd42d9e850a28e49df826d6937c2cffee54c595c0a6581995f5df599bfc392124e934cd9c00e0281d13f7b631741fe921f2d03b8b5d0dcd9177f081ad0ec4d23ab2b0bfeeae1738503d39d026b46902d1fa892c8d37e05ee7a709ffc92a0275462d527d134ba602e1fb26145c698fd6124e06acd00c73b5df43345b49f5a7c60fbcaa23c923634f7dc9608efccf1dc4b3c287a73398ba1415924351be65a4af65f7b74a7662fb548b0fe6f05f520413365ffe0ba27dd777281300d148d84607c5dbf3d994d219cbb4cb7d0c7711e4dd49bb1537dbee2a00564ed7fac6f83d2ac47436502ecd348cc3aba39821e61d84a27e3362e3a718e2d4101973041143a04fd757119f0a2f4bd4319206a99e281f23a09896e54348b875dc40ba6e26ecec36151ba8902574f2f228e3e37692f577df0c7615296fa13fba1d7cfcb7c94c14a4dc277db7f5472a4817efeebc943e28661e774ef319d29b2573bb30573e7b995565d264227706acf6ddb583e19abcbfba2ac73cfb0bb95edbe49b6df45ba78762bc1304aebb67bafc6fa20afb84c0e8fe0c8ca481e83a2a76f97bc2d37afcedc84361b40f0cb0222927612dbbc4218248362cc7116a23bfceba2471605e21c8b380ff0da38f53851630b6d7ccc2eda7e6c5cf5e0600dd2316b480cf59e99be4264cdf7c80
#TRUST-RSA-SHA256 a3b8bfb41209e38d47dc1dd9b332bef9fe799e730c4ee1315e75aa1ea6f1e11c2b19378f690a885f60fab0ba93028c55ab7f3d4319793f00fcc03d018b29de97187d340b121277fbd69e9780262c455d943d9e3e34092c205ee651813d59c9828cc52c2b93a9f81b4f916927dec562af22197fa00ba1acb2f4ad5bfb5a4f2ea7eb62f7c1fa882b7a5c55899037f8873a7ebe60cacf7df56e10b4e1bfc8b3b43feddb1ea8f65fe654dbba97710bbc0106bb91e17e1a1a5bccdec22500f0248b31c056895239e1d084f7672ee5647904e65b4b9e7e58b1c9445bb80f7bc8d46723c947bec31f8183b06259b688f38a0a25caddaadd17c3a2656493d407465d005f59a6f8bc2f3810a89756cd8c4263d8431d1e8498230c18700afa14ce0261cb58c2be52985b7179fb3debdcdcab77872d0b46740e03c00c8012c43d22c4dc2581918764ef0419c6297e28ad49cb8ef74ff63efceb8a441d885bfebd1638f86ad5f001e9a7161a63be8178e12ca44285c254798b4f5d755dff8cb1e849cdd86695b748b5adf510e606e8769474e7a8beaee21cb3280b97da0e685c7163fc4c6655dfdd101950a67814ee6e17b7481fd5a670cf894fe994c748ab582e9191c8059298552b6a7d70cf24d37b759b0626f6c86d9e7885fce50062850f80d393808edf097a555bc2e91adcf445514d9f27f4567223a3146b7aef72d3a81cbb75583f0d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(90707);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_name(english:"SSH SCP Protocol Detection");
  script_summary(english:"Detects SCP support over SSH.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host supports the SCP protocol over SSH."
  );
  script_set_attribute(
    attribute:"description",
    value:"The remote host supports the Secure Copy (SCP) protocol over SSH."
  );
  script_set_attribute(attribute:"see_also",value:"https://en.wikipedia.org/wiki/Secure_copy");
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");

  exit(0);
}

include("global_settings.inc");
include("ssh_lib.inc");
include("ssh_scp_func.inc");
include("misc_func.inc");
include("obj.inc");
include("audit.inc");

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

sock_g = ssh_open_connection();
if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
info_t = INFO_SSH;

port = sshlib::kb_ssh_transport();

if(!ssh_scp_init())
{
  ssh_close_connection();
  audit(AUDIT_FN_FAIL, 'ssh_scp_init');
}

ssh_scp_pull_file(location:rand_str(length:50));
ssh_close_connection();

ssh_err = tolower(get_ssh_error());

if('no such file or directory' >< ssh_err && "scp warning" >< ssh_err)
{
  set_kb_item(name:'SSH/SCP/' + port + '/Supported', value:TRUE);
  security_note(port);
}
else
{
  set_kb_item(name:'SSH/SCP/' + port + '/Supported', value:FALSE);
  exit(0, 'SCP not supported over ssh server on port ' + port + '.');
}
