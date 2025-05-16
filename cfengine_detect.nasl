#TRUSTED 6bfc04e3014fda320a9a92bbd953edfcb453e57714da485d59cc33aab61b19123289e3835f3bc724c2f5420ca2219e4d608e90b5c96ac689d560c11eabca0786eee1e7005d69990261791b506aea60b025861aab921ec0952ce2b2955079f1c9cdaf515232f0005eccc3b57944e60847670f74dc4f786a4e3cee73615dda9853a968c29237a206dd1675322bcf4ec77a883995e2c610f46ef2d161744739c317df60961af6e0efb2775a3a4e1619de4aa272c7cb72ee9df37ef06f2f82ac575c0ee3465b8158876558a3e6dc3a25945689c52905b7ba9157dcad3ff234dac71306ded36203bb9c1ce7373935a3dd14c420b676dd94852f730e4ec3e30c538beb88b0a4582964954fb38937ab8f0ac6ccf2cc50cc9615a725b56fc8efd4e9bb2c716448fdcde38c0e46c5e1b0b1a8646484ace0187d4adad560b1b7b3af5f65e6464bafcd1f8d05eb8073b3ced57f84828561ba5700245f172106a11d0f478588089b396eb6e76899ea3df08a08ea48bc3580d80df3f8dac4e2202df35435bd64b7eb84fb60b359802bcfb14eaf5955a2b2b1b4d98ca576ddfd67911ba8bbff5b668c6287ca1c887444d123dc8422daf4649e8f77a5ca742512fa60433a9ade338b31cc5d15c8c29754dbd2b7b90bbfac140acc5481dbecb06e453dae9b14ab09ffd5f1b3310f0da562939a6e757d5353ffffbbe57a54a1b2018945ff623c8f77
#TRUST-RSA-SHA256 49ca41877a833c08a791e23b9818291fac3552124a77583ff08bf1a239afeeea53e50008d75a1315378e85dbfc1838eb44e65441f31edf0c6f817662714265cf599436fec7e6be904eb8744dc8ce146660036c351406b1b0710299250924680e18b939245730161c2ea1e2ce548a603cf0b29534e82310e769c2e7f935a05cde9086daacaad58d34e8da2dea5dba66199eacfa2182b400e9b91f9befb7c65916d5a2a1338c722683e3f21a603075113e7de98cbdbc7aecdca01673cb1455572f712fb92f63466c1ea07a2266d6fbe592783739b0f1a1770f839ef75c7ea36d4b036c2e2c00dff4b75319af39b1f8cc6416fd124dff666a9bd9a52744676e6adba528ac713dbc9dbad146e093241f08d9de4d3df26ba67a8175117f3dbe1333d30094113fa2050ca46f817e6b8cea260d7377ffcf3e23bca33adfa08ecd7f3113aafd015c1a8f47e609e7482a44c079440a27bd85c9e7fab2a791cea422b2c76b891541d1e4c27ef214dfa657af7dd426fd7089b1b3ef9a17ede2d5e269d7199c0910ff6182be50197199df6d5912687f3fba87ba24fdc38e96e0eee0030f4a27ffdad5f1c63d59283bfb3724700d64b68f96a529620377993973f575e48b137cbf853d0e686fbb4f98fb1909f20b9e7a5e9f6005c6044cf27ffb2087fe08152a43eb1327ab9ed6b3e65a7c313b7ab13acdacde1b6a9a50a66eb323926723659f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14315);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_name(english:"Cfengine Detection");
  script_summary(english:"Detect cfengine.");

  script_set_attribute(attribute:"synopsis", value:
"The cfengine service is running on this port.");
  script_set_attribute(attribute:"description", value:
"Cfengine is a language-based system for testing and configuring
Unix systems attached to a TCP/IP network.");
  script_set_attribute(attribute:"see_also", value:"https://cfengine.com/");
  script_set_attribute(attribute:"solution", value:"N/A");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:cfengine");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2004-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "process_on_port.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include('local_detection_nix.inc');


ldnix::init_plugin();

var ret, buf, res, ver, runner, servs, serv, report;

if (islocalhost())
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}

buf = info_send_cmd(cmd:"strings /var/cfengine/lib/cfengine-enterprise.so");
res = pregmatch(pattern:"(CFEngine) [eE]nterprise (\d.[\d.]+)", string:buf);
if((!isnull(res) && res[1] >< "CFEngine"))
  ver = res[2];

if (empty_or_null(ver))
{
  buf = info_send_cmd(cmd:"cat /var/cfengine/state/previous_state/software.cache");
  res = pregmatch(pattern:"(cfengine-nova-hub,)([0-9.]+[0-9]+).+", string:buf);
  if(!isnull(res))
    ver = res[2];
}

if (info_t == INFO_SSH) ssh_close_connection();

if (isnull(ver) || "not found" >< ver)
  audit(AUDIT_NOT_INST, "cfengine");
else
  set_kb_item(name:"cfengine/version", value:ver);

runner = FALSE;

servs = get_kb_list("Host/Listeners/*");

foreach serv (servs)
{
  if(serv =~ '/cfengine/' || serv =~ '/cfservd')
    runner=TRUE;
}

if (runner)
  set_kb_item(name:"cfengine/running", value:TRUE);

report = '\n  Version  : ' + ver +'\n';

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
