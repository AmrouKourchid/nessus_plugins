#TRUSTED 1517329a924351ad315615940530654247b586c515a6e99bc3456b745130c23d555761d4fcd8371cd60ec83342623925956309d41d3b9900c463e0b75e7859ee7cb4e17819b2526e5a439b2474859feb64c2efcb9f52959b2aea8830b32e56d7da11ca1923278b7a23cbdf9fd8c93beab914be250ec88439c2ed5e8312095eaeef6c0fc1493f1138402376d2c410d3735edf7f6e64b52de7a5ca79e8875240bd97686e19e1fed8ae45194e4eaf9dce93805287754bd647791a9c5dfd059a1483530c57f636b0db2cee100cbfb9b10f5e3b0fa6bbc4a14a777d0ec0809f619c4e9ebea1671eedeac642dae79febab76461da4bf5e6006021c6069f345df07dfe76b30ef884b70147cc13ebf8f1f8140ed2193da0bab2332b6a06b0323330422625f15807c5f937547fa5548ca66440dad466421bc7f30851c77d9fd822cde6a7c635cb4aa4dc98ddc989fb52e035da939bee0f95c634eab87b8168a80cdc0f8b8e11add256f42cff367c992273718ff7952083bc2855942415ef64e397b4b247acc51f9b5f9894bdbbc84b6026aee18f3a94134349dbadb9b85043a7d1411f9db54bc6eff5f8b3663166668543532a63e09ee886aa4e9350ec090951d633edc429142608e29572f6127d1f84d5a144a715fe79553eeb217d09a78990d5a480867325cc78d2a5e7b11c2372ae5b41effb9d8ec5bf1bc604aa722fd2e1d1f2a914e
#TRUST-RSA-SHA256 2bdfa457fd5a16f68ece631ec58be758cc07fd970f218739f2e7ec2fccd2a1538b952363874793f599f3a4ac6425bd3ff7208def526fb5c282076d8c9262a6b5b6709e5905c034863669e9232208411be1fed11e102c86b980a1983566d3f4a5b087c149bb4936b04d72278bf5b43115959055bbb85528463a5f653ef1dbc472e4cb0e5353823a111fa97b1ad1b3f9a2582214d55aeec250591eb73c05ec9465142c3d3656931ab60d6f1e2f4b5db691c65e8117ff30069976f9812c73430f4106636bd60fc18d08621aadf2db6cd527a66b271b8765f755a55244b9f0ba329d54e4e312a71769c1360fb802c09d94bb8dff441e5ad08b2282fdd4c0600733f7490cbc2a798b4f1045779ba94de2082408cf678b2a1d3c1212f360da1de8c1e56ff48ad278a6964574373bcfabe9225925679882403099cb205cc92ea5d3ecd65887179580abf5ea724c961644886251105229b1ba245fa3ec357cd3638d27a31994c43bb6fda3084766d67ccbc381d82a8330fb1e2c85d53e32c17dadbf19ccf91fecc053c344a390fbe91ce9dea5c9fd2f1053ad3191fc603e27acb80144803664ae6b69481ef2aaba68e54fedaffc389c746fe88d088584c552df997886d2662516988dbd5088cb54fe3b19ba783d71d139861c075218c870ef837366fe532444843e5b11c233b48b24daf60b90ec0a7bdd659c9ed1f8ae95b07171a2bc42

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131286);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/30");

  script_name(english:"Command Builder Initialization");
  script_summary(english:"Initialize command builder library.");

  script_set_attribute(attribute:"synopsis", value:
"Query host to initialize command builder functionality.");
  script_set_attribute(attribute:"description", value:
"Query host for the existance and functionality of commands wrapped by the command builder library.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl", "docker_for_linux_installed.nbin", "docker_for_mac_installed.nbin");
  script_dependencies("containerd_detect.nbin", "cri-o_detect.nbin", "podman_detect.nbin");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("command_builder.inc");
include("sh_commands_find.inc");
include("spad_log_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

uname = get_kb_item("Host/uname");

if (isnull(uname)) uname = '';

if ("Linux" >< uname ||
    "Darwin" >< uname ||
    get_kb_item("Host/Solaris/Version") ||
    get_kb_item("Host/Solaris11/Version") ||
    get_kb_item("Host/AIX/version") ||
    get_kb_item("Host/HP-UX/version") ||
    get_kb_item("Host/FreeBSD/release") )
{
  enable_ssh_wrappers();

  if (islocalhost())
  {
    if (!defined_func("pread") )
    {
      spad_log_and_exit(exit_level:1, exit_msg:"'pread()' is not defined.");
    }
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (!sock_g)
    {
      spad_log_and_exit(exit_level:1, exit_msg:"Failed to open an SSH connection.");
    }

    info_t = INFO_SSH;
  }

  command_builder::init_cmd_runner();
  sh_commands_find::init_find();

  if(info_t == INFO_SSH) ssh_close_connection();

  exit(0);
}
else
{
  exit(0, "Unsupported operating system.");
}


