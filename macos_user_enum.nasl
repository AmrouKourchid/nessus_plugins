#TRUSTED 4b8c28fb5525eaba0ca43c0119210e5c4a641d629ea803e0831239e37b52601fd89766584f71e17de72842c1a6a9aff6038f9d3163786c70a49911f8351c65e6a65c4eba64e6c1f1e298f2cc4f0dd241152fa85326ce2f9d4c4fb970fcf3bb73b0b456464ebff2ef815f2af6b27ea8a0d08438cf6463d8a011710f5d847705b568eac930540aed01312edd5ef8a0ba3ff61ceead43ba42a35571e1be5b93f99775f7ab10d29ca233cbcd5ab66bd6e0197a31c6ee7826f0b2ab549fbb43c8647abc57cf089695e3ee509d9ed244efc710f6d95bd1aa25f85cea376ded0824762b2e30928808d171194700c67186204d6e84a3225c0ce079a6decdf3f58c49e870d5a5eccb3fdce31f9a24ceb9fc3b9e00ed3e2703bd322aa4ba094b70a27873d507b1e3a9c9e47fbd9f5fea2efb2b67fcedccc5e542f07c5635a9068f952166f2b2e3f9184aa37bf42536efdf3be73d24fb603ddf6281b7f2cac99ea60bb667cac17d5bdde477706d14e84f08f64db51fba2050bd3edef472cc3606a5ec5e711e1e53e9139443d243660192bc0ae172dddc42a006e18d79810c663060e89e5c4d4068fc8bae40771bc047fa89cb6abd4ee852fb1e015047d69436c89e1311b91824ba05848c9fb0b4326b62d9b9182ad4feed435137a876b54e16340910feb3b002054a58a0685c94e09fc656a9f40db07d24f8443859e86a7002ef4ffab0270f
#TRUST-RSA-SHA256 b1bd3c8fb2bf2109d7b70e30e81781f03084409e5807863231f48cbb7a3840061e202333eed0d99f169944b4520fb0a1a1b6c2a0b1764724ead9b11ef9f3f8a23bf016c9aeb6076841157e1d4b96da13f0b6d8f637de7d3333935a3ae0db7b586612bb85453e461b257af1f814b19adfa3dd7c633131c60b2fa0b129dd0a894182e75a2b96c7d1705f202db260f1eb644ad7104dee4debfbe7fa73c08df47e0d17aad5b4dac84c4b302605f3b454b01a742a4ac81dd218260cac8614946868fa1b5db03d8ab583546e9ec1373779a94fd7ea0fe4b5cd6607d5dbe704581a0f8dc012d77dca934838a8d9b6841e30eb9afb0ba93d3ed00fad72ac86ac900d4da3c7fd393743ad5a1c4a843e3f1a8131f8e13b0a0864cdc3aa4f6921982deb15d3969701b4bf57f1f4249c8d0dda982e3ef206d84e10168a27c1141ceae0599187e04244392bb3bfbafae78bf8d3cce45283226b58402c87e4a432cfa0e310b05985f3c8c441574181c1aaa13047c91a1749fb39af7836fdb94be98ecf376bd18774207662c2058d1cde7b6f3cfb96a3f12e8941d468bc54618465a8d65761e6cb27b3dc7050c8c50cb67bebfe357acbfc8b00be08a99ef4dda7b85d40151f362a682d42b56ddfc1a42090d126944aaba2ae6b06ded6c7c359325164c47bdad4e98a76c565a38c152c66782b09e597d17ba29cded0836728429be37cf10eb10e58
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(95929);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/26");

  script_name(english:"macOS and Mac OS X User List Enumeration");
  script_summary(english:"Lists users on macOS and Mac OS hosts.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate local users on the remote host.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to extract the member
list of the 'Admin' and 'Wheel' groups on the remote host. Members of
these groups have administrative access.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include('ssh_func.inc');
include('macosx_func.inc');
include('mac_dscl_output_parser.inc');
include('mac_accounts_object.inc');
include('mac_groups_object.inc');

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

var os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running macOS or Mac OS X.");

var cmd = "/usr/bin/dscl . -readall /Groups GroupMembership GroupMembers GeneratedUID RecordName RealName PrimaryGroupID NestedGroups SMBSID";
var dscl_groups = new('mac_dscl_output_parser', exec_cmd(cmd:cmd));

cmd = "/usr/bin/dscl . -readall /Users accountPolicyData NFSHomeDirectory PrimaryGroupID RealName RecordName UniqueID UserShell GeneratedUID SMBSID";
var dscl_users = new('mac_dscl_output_parser', exec_cmd(cmd:cmd));

dscl_users = dscl_users.dscl_obj_data;
dscl_groups = dscl_groups.dscl_obj_data;

if(len(dscl_groups) == 0 || len(dscl_users) == 0)
  exit(0, "Could not retrieve users or groups using dscl.");

var groups = new('mac_groups'), member, res, nested_group;
var tmp_group_members = {};
foreach var dscl_group(dscl_groups)
{
  if(!groups.make_group(key:dscl_group.GeneratedUID[0]))
    continue;

  groups.set_name(dscl_group.RecordName[0]);

  if(!empty_or_null(dscl_group.GroupMembership))
    tmp_group_members[dscl_group.GeneratedUID[0]] = dscl_group.GroupMembership;

  if(!empty_or_null(dscl_group.RealName))
    groups.set_real_name(dscl_group.RealName[0]);

  if(!empty_or_null(dscl_group.SMBSID))
  {
    groups.set_smbsid(dscl_group.SMBSID[0]);
    groups.set_group_scope('domain');
  }
  else
  {
    groups.set_group_scope('local'); 
  }

  if(!empty_or_null(dscl_group.PrimaryGroupID))
    groups.set_pgid(int(dscl_group.PrimaryGroupID[0]));

  foreach member(dscl_group.GroupMembers)
    groups.add_account_member(member);

  foreach nested_group(dscl_group.NestedGroups)
    groups.add_group_member(nested_group);
}

var accounts = new('mac_accounts');
foreach var dscl_user(dscl_users)
{
  if(!accounts.make_account(key:dscl_user.GeneratedUID[0]))
    continue;

  accounts.set_name(dscl_user.RecordName[0]);
  accounts.set_uid(int(dscl_user.UniqueID[0]));

  if(!empty_or_null(dscl_user.RealName))
    accounts.set_real_name(dscl_user.RealName[0]);

  if(!empty_or_null(dscl_user.PrimaryGroupID))
    accounts.set_pgid(int(dscl_user.PrimaryGroupID[0]));

  if(!empty_or_null(dscl_user.SMBSID))
  {
    accounts.set_smbsid(dscl_user.SMBSID[0]);
    accounts.set_account_scope('domain');
  }
  else
  {
    accounts.set_account_scope('local');
  }

  if(!empty_or_null(dscl_user.NFSHomeDirectory))
    accounts.set_home_directory(dscl_user.NFSHomeDirectory[0]);

  if(!empty_or_null(dscl_user.UserShell))
    accounts.set_command_shell(dscl_user.UserShell[0]);

  if(!empty_or_null(dscl_user.accountPolicyData))
    accounts.set_password_metadata(dscl_user.accountPolicyData[0]);

  if(!empty_or_null(dscl_user.RecordName))
    accounts.set_accountType(dscl_user.RecordName[0]);

}

# Consolidate group membership data in both objects
foreach var group_guid(keys(groups.groups))
{
  groups.focus_group(key:group_guid);
  foreach member(tmp_group_members[group_guid])
    groups.add_account_member(accounts.get_account_guid_by_name(name:member));

  foreach member(groups.groups[group_guid].accountMembers)
  {
    accounts.focus_account(key:member);
    accounts.add_group_membership(group_guid);
  }
}

var user_groups, user_data, res_usr = '', info = '', info2 = '';
var acct_users = [];
foreach var user(accounts.accounts)
{
  res_usr += '\n' + user.name;

  user_groups = '';
  user_data = '';

  foreach var group(user.groupMembership)
    user_groups += groups.groups[group].name + '\n         ';

  if(user_groups) 
    user_groups = strcat('Groups : ', chomp(trim(user_groups)), '\n');

  user_data = strcat('\n', "User   : ", data_protection::sanitize_user_enum(users:user.name), '\n', user_groups);

  if(user.name !~ "^_")
  {
    info += user_data;
    append_element(var:acct_users, value:user.name);
  }
  else
  {
    info2 += user_data;
  }
}

replace_kb_item(name:"Host/MacOSX/Users", value:res_usr);
replace_kb_item(name:"Host/non-service/Users", value:join(acct_users, sep:'\n'));

groups.report();
accounts.report();

var report = strcat(
  '\n----------[ User Accounts ]----------\n', info, 
  '\n----------[ Service Accounts ]----------\n', info2
);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
