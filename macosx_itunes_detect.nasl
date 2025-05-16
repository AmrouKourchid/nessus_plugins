#TRUSTED 7defe260cd30905661da4c6fb2cc8bc0171e3f8707892a50df575363729a4729afb249d2d075b7bc03ff04ea3a53f54ebad03388af5622d0f5da0af3c3b0eac610e3bc9f50a7a9d2ecd3305a465797d7ae613f7721e45ce663308a7bbd5142ac9fa9ff46f99eec9103bd2c58ab5730a14fe303135fc3b4462470ab6467bc12d76d8ba527297514c83ecf0711fc4f1a852578eddd76d9198cc1b4a55de03dd0aa17d168f79f775a07c3daeb4278b3b753434a69bdf122f35cf40f4b78b1b00b881204193202304f6d1c7d2d456d926322e95a98d11eb78955ee0aae95428139e65fab8aaea3f6749a105c3fe513536238b43b7335a1db1fac46701ab2e26a250d1816f81839dd042c4413728316bdfe6ef5e75e94b2f873a9c8f15ac9e3220df210bef8f759350175a5ee27208e9a069acbda20b5a1b4953edb79853c807e813e2a851c44ed495204592c77b717ef741648883214347705b5ac285d7f5668e5edd86c2761da37ba5c9b6ebfeee9895b46624040c6486deb19a83e1393cb97802ca1d573a4834d6814d12dbd781d97b50b195dea084bbb84623d1f70070c4b53f7aeefe95037f17370eb795753669ac1888d82139f33bf986f1666b5f0cee297cda3942c0e3f3ca273d28f7b882e976efc7725aa8b965de32f2f1208da5b7a011786a1d9d456e4b12040979cb5d90847c7f3a45eb28ce28f449bc855fa7749dce8
#TRUST-RSA-SHA256 6527f23cc7f8408c090121df6a9496b01a793713b7b4a45861aa27b6b0086efa397ea8e7a6f93a9a89bdb5b0b12fa72b475571f5106896dbc9aaa0e47d5ae47a088f7200232e305224fab895d923ee64ea3708df89cadbcb6a20c89a0851d5fc1b2d2142df1d7ad366868d5f7b700f0441b81c3397ad6f905812055a0757ddd9fb917eb9ccfde6c951388d922228ab2c0b10b1fdcee7e717af60ae258c258e8f16bf65eaa0d6d5d1c9890c7dfdf7f7bb7c07deba13929330cf3029dd58fc0c78119d76b8ae48b5a0afe71c75431e0de6afa3034e9a44685e0b86af6f803bb6d10c7e4cc9222179073c3c96ee3a8fac4f254910d4ff0be6c9382b72fdf47e6d6e49efdfc57795a09e6752502d961c5b44ee9f127e50df46b83bfae39029b6406f8aa82c09925cd1a2484406af9cd01abcb7f666bde492f24155d02630a3251dbd327f3044f862a81875805bea6ab4fa782e3b0051b7df390b48ad203e0248789f089f585774ecfd406ada58bc163b9c64282f829ac3160b1b663a242f8001767e624c222459a98457dee33d6ab296f9fcb547594f06fe9898ba68e77e11398d3ee2baa701e50f8d48e3d3467d93d8e6967e499a2adfb3285f3380fb484d0c358a3d16c156144a5a05c11ce08812a0d35cf9764e9952a3734c1323bf934c02f8aabf6c8b08dbe5f2ae5dc60e95e5af9af7472fd63e149351002ae507534192c970
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25997);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_name(english:"iTunes Version Detection (macOS)");
  script_summary(english:"Check the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"Apple iTunes is installed on the remote macOS or Mac OS X host.");
  script_set_attribute(attribute:"description", value:
"Apple iTunes, a popular media player, is installed on the remote macOS
or Mac OS X host.");
  script_set_attribute(attribute:"solution", value:
"Ensure the use of this application complies with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/07");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2007-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");
  exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");
include("misc_func.inc");
include("global_settings.inc");
include("audit.inc");


enable_ssh_wrappers();

cmd = GetBundleVersionCmd(file:"iTunes.app", path:"/Applications");
uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  if ( islocalhost() )
   buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
   ret = info_connect();
   if ( ! ret ) exit(0);
   buf = info_send_cmd(cmd:cmd);
   if (info_t == INFO_SSH)
     ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get version - '"+buf+"'.");

  vers = split(chomp(buf), sep:'.', keep:FALSE);

  register_install(
    app_name:"iTunes",
    vendor : 'Apple',
    product : 'iTunes',
    path:"/Applications",
    version:string(int(vers[0]), ".", int(vers[1]), ".", int(vers[2])),
    cpe:"cpe:/a:apple:itunes");
}

report_installs(app_name:"iTunes");
