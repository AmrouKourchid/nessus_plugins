#TRUSTED 6cf429518c5c4f6fb7364fd67ebff56c582feb279915cd9ef463736bf5d5d9e1feb29aa580bd986b1a49fb25b5ee3e598358fa2b317afd862093c05c64ae606e80cf33fe6e05a56f023df4b500a6d2e14b2fe712c9e980b33efbeba8de0d751e9f3b3c009834da44c7e09587c7fb613d94d6d735a4e87fd84b7425e7e8c04f12f4a98ff08442c140bfd57426d0ae3b0856cdfda9c3bc5668ddffb83045a558445a36142bcba952b85457770f453d74f8c7c8b4cf7ff0e7cba51dec2602055af2583d588cf2a5dca6ee938f3cb70b9f5c799e42d4c7e0379db4b966a3eb2eb34d0839ec36e2cc4414ff0d532349790f17f73d50368c635c501592c45925c001bce7762254ccbef741473b013ec438f1766f33b8e205ca59dfb9e523952b6ea888387b6fe0b6401ed7ae9c4d8f5bdd40ba04e586b6ebaa66c1c16fba44fed8fbcfa8f85b2c24fff8c8576ca4353163b9489f431aa0ab7a5d0232d1191f8f42ee059f908bb0ebf12ad5c8ebb65fbfb6cc08a7f789a582452b8c7df47496983cc33c8ca1d0fa81733aa1b80f42d6f54bc30c10ac1f3a5ca45349903673ba902a74d6ef9708412f9dc5eb4c1c268ead7b0b6e19d7c51b3fc25e70e0bba09ea127643148927c76106fdc026da55a7aab868782e1c16a94d14ef0f074fbf96d3515cb9d28722af288a405118cb9de8fab889b7b9e08fd0f89c137a4a8d25a4d608d2404
#TRUST-RSA-SHA256 7e2f3590f9cddabf9c169dfd7136c54a5840eaf17aa43c20c5339c886fef9adf2391e6661998ba28f0c294f5b6f235bab8c5d0f19dab6712acc812e8f4ecc301c04c48cfca7ee4835f5c1763427a9af295bf54812c178e37debdf21b3c38a39fc059ae3be03a825a2879edd2e897b077bd0309cc495bd2cd89ed508e25f95776e530bd9df518475deb62712b30bdfb11451ff2dd420bb64c8ca528054070de5f6294ab7b1881dac24f4f05a5fe1b2a05e9533ee9336eefd941a3a800c389502517bc662ffa0569606236d225a1d07d06e65eade646e5789ef2374a074e539acb4439dce09bb7b67f2d209d6beca2cf95a66e3c8deaa924b246c9d3267138b0853439003219b905cc1e3ee612180ff6af258c79f331a6ca994be1f665cdc3b1f2a85cb12be33b1791ec1ce2812ac03a05a0a04d4329a51821733c816b5d0fd54a889e1911d8a376cde3b69ec6898dd4dd7a2b533de119845e3844bb50aa674ca9b6b7d1890ee2781023989a209ce093339bd060b9383888b77d6857f428befe4fb1f321a2722e8b6f2874dc1da382cfe70fc4b642450d2e970f19b10268ea89f31809d3fe209e68a694fa7bf9541580a9896685e7d0770e6a7c226aa086515721b4fc6f041028c1f7efc4f296cb1813bbde3c30570afbb3ab218c480aa57f0ee7762757c682ec22f18a112eb956fb98a150eb6386e2bec718999e93ab9813f412
##
# (C) Tenable, Inc.
##

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(95928);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/26");

  script_name(english:"Linux User List Enumeration");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate local users and groups on the remote Linux host.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to enumerate the local users and groups on the remote Linux host.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include('local_detection_nix.inc');
include('linux_groups_object.inc');
include('linux_accounts_object.inc');

##
# Calls id utility to get data about target user's uid and groups and stores it in passed arrays.
# @param [user:&array] A reference to an array representing user data created by get_domain_users_and_groups().
# @param [groups:&array] A reference to an array representing groups created by get_domain_users_and_groups().
# @return NULL - data is retrieved by filling user and groups arrays.
#
##
function gather_user_id_data(&user, &groups)
{
  var cmd = "id $1$@$2$";
  var results = ldnix::run_cmd_template_wrapper(template:cmd, args:[user.username, user.domain]);
  if(empty_or_null(results))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'id call failed, exiting!');
    return FALSE;
  }
  var user_match = pregmatch(pattern:"uid=(\d+)", string:results);
  if(!empty_or_null(user_match))
  {
    user.uid = user_match[1];
  }
  var default_gid_match = pregmatch(pattern:"gid=(\d+)", string:results);
  if(!empty_or_null(user_match))
  {
    user.gid = default_gid_match[1];
  }
  user.groups = [];
  var groups_part = pregmatch(pattern:"groups=(.*)", string:results);
  if(empty_or_null(groups_part))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:strcat('No groups found for ', user.fullname, ' exiting!'));
    return;
  }
  groups_part = groups_part[1];
  var group_entries = split(groups_part, sep:',', keep:FALSE);
  foreach(var group_entry in group_entries)
  {
    var group_match = pregmatch(pattern:"(\d+)\(([^)]+)\)", string:group_entry);
    if(empty_or_null(group_match)) continue;

    var gid = int(group_match[1]);
    var group_name = group_match[2];
    if(empty_or_null(groups[gid]))
    {
      groups[gid] = {name:group_name, users:[]};
    }

    append_element(var:groups[gid].users, value:user.fullname);
    user.groups[group_name] = TRUE;
  }
}

##
# Discovers domain groups and users by scanning /home directory and calling id utility.
# @return A pair (array) of arrays: {users, groups}.
##
function get_domain_users_and_groups()
{
  var cmd = "ls -1 /home | grep -E '.+@.+\.[a-zA-Z]+'";
  var results = ldnix::run_cmd_template_wrapper(template:cmd);
  if(empty_or_null(results))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'No domain users found, exiting!');
    return [];
  }

  results = split(results, keep:FALSE);
  var users = [];
  var groups = {};
  foreach(var res in results)
  {
    var match = pregmatch(pattern:"(\S+)@(\S+)", string:res);
    if(empty_or_null(match)) continue;
    var username = match[1];
    var domain = match[2];
    var user = {'username':username, 'domain':domain, 'fullname':res, 'home':ldnix::append_path(path:'/home', value:res)};
    gather_user_id_data(user:user, groups:groups);
    append_element(var:users, value:user);
  }
  return {'users':users, 'groups':groups};
}

function create_account_object(uid, usr, home, shell, default_gid, &users, usr_acct, scope)
{
  if (typeof(uid) != 'int') return NULL;
  if (!structured_accounts.make_account(key:uid)) return FALSE;

  structured_accounts.set_name(usr);
  structured_accounts.set_accountType(usr_acct);
  structured_accounts.set_home_directory(home);
  structured_accounts.set_command_shell(shell);
  structured_accounts.set_account_scope(scope);

  # Set default user group membership
  structured_accounts.add_group_membership(default_gid);
  structured_groups.focus_group(key:default_gid);
  structured_groups.add_group_membership(uid);

  var gid;
  foreach var group_name(keys(users[usr]))
  {
    gid = structured_groups.get_gid_by_name(name:group_name);
    if (!gid) continue;

    structured_accounts.add_group_membership(gid);
    structured_groups.focus_group(key:gid);
    structured_groups.add_group_membership(uid);
  }
}

function create_group_object(gid, name, scope)
{
  if (typeof(gid) != 'int') return NULL;

  if (!structured_groups.group_exists(key:gid))
  {
    if (!structured_groups.make_group(key:gid))
      return FALSE;
  }
  else
  {
    structured_groups.focus_group(key:gid);
  }

  structured_groups.set_name(name);
  structured_groups.set_group_scope(scope);
  return TRUE;
}

ldnix::init_plugin();
info_connect(exit_on_fail:true);

var cmd = 'cat /etc/passwd';
var etcp = info_send_cmd(cmd:cmd);

cmd = 'cat /etc/group';
var etcg = info_send_cmd(cmd:cmd);

cmd = 'cat /etc/login.defs';
var etcl = info_send_cmd(cmd:cmd);

var domain_data = get_domain_users_and_groups();
var domain_users = domain_data.users;
var domain_groups = domain_data.groups;


if(info_t == INFO_SSH)
  ssh_close_connection();
if('Permission denied' >< etcp || empty_or_null(etcp))
  exit(0, 'Could not read /etc/passwd.');

var structured_groups = new('linux_groups');
var structured_accounts = new('linux_accounts');

var checkuid = FALSE, uid_min, uid_max;
if('UID_MIN' >< etcl)
{
  var match = pregmatch(pattern:"UID_MIN\s+(\d+)\s+UID_MAX\s+(\d+)", string:join(split(etcl,keep:FALSE),sep:' '));
  if(!empty_or_null(match))
  {
    uid_min = int(match[1]);
    uid_max = int(match[2]);
  }
  checkuid = TRUE;
}

var users = make_array();
var groups = make_array();
var user;
var domain_user, domain_gid;

foreach var grp(split(etcg, keep:FALSE))
{
  if (grp !~ "^[^:]+:[^:]*:[^:]*:[^:]*$") continue;
  grp = split(grp, sep:':', keep:FALSE);
  groups[grp[2]] = grp[0];

  create_group_object(gid:int(grp[2]), name:grp[0], scope:'local');

  foreach user(split(grp[3], sep:',' , keep:FALSE))
  {
    if(empty_or_null(users[user]))
      users[user] = make_array(grp[0], TRUE);
    else
      users[user][grp[0]] = TRUE;
  }
}

for(domain_gid in domain_groups)
{
  create_group_object(gid:domain_gid, name:domain_groups[domain_gid].name, scope:'domain');
  foreach(domain_user in domain_groups[domain_gid].users)
  {
    if(empty_or_null(users[domain_user]))
      users[domain_user] = make_array(domain_groups[domain_gid].name, TRUE);
    else
      users[domain_user][domain_groups[domain_gid].name] = TRUE;
  }
}

var report = '';
var report_usr = '';
var report_sys = '';
var report_dom = '';
var usr, uid, home, shell, gid, usr_acct;

foreach(domain_user in domain_users)
{
  usr = domain_user.fullname;
  uid = domain_user.uid;
  home = domain_user.home;
  shell = 'unknown';
  gid = domain_user.gid;
  create_account_object(uid:uid, usr:usr, home:home, shell:shell, default_gid:gid, users:users, usr_acct:'user', scope:'domain');

  report_dom += '\n';
  report_dom += join( 'User         : ' + usr,
                      'Home folder  : ' + home,
                      'Start script : ' + shell,
                      'Groups       : ' + join(keys(users[usr]), sep:'\n               '),
                      sep:'\n');
  report_dom += '\n';
}

var line;
var usr_acct_list = ["root"];
foreach line(split(etcp, keep:FALSE))
{
  if(line !~ "^[^:]+:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$")
    continue;

  usr_acct = FALSE;
  usr = split(line, sep:':', keep:FALSE);
  uid = int(usr[2]);
  home = usr[5];
  shell = usr[6];
  gid = int(usr[3]);
  usr = usr[0];

  if(checkuid && uid >= uid_min && uid <= uid_max && shell !~ "/sbin/nologin$")
  {
    append_element(var:usr_acct_list, value:usr);
    usr_acct = TRUE;
  }

  create_account_object(uid:uid, usr:usr, home:home, shell:shell, default_gid:gid, users:users, usr_acct:usr_acct, scope:'local');

  # add default group in case it wasn't already added
  if(empty_or_null(users[usr]))
    users[usr] = make_array(groups[gid], TRUE);
  else
    users[usr][groups[gid]] = TRUE;

  usr = data_protection::sanitize_user_enum(users:usr);
  if(checkuid)
  {
    if(usr_acct)
    {
      report_usr += '\n';
      report_usr += join( 'User         : ' + usr,
                          'Home folder  : ' + home,
                          'Start script : ' + shell,
                          'Groups       : ' + join(keys(users[usr]), sep:'\n               '),
                          sep:'\n');
      report_usr += '\n';
    }
    else
    {
      report_sys += '\n';
      report_sys += join( 'User         : ' + usr,
                          'Home folder  : ' + home,
                          'Start script : ' + shell,
                          'Groups       : ' + join(keys(users[usr]), sep:'\n               '),
                          sep:'\n');
      report_sys += '\n';
    }

  }
  else
  {
    report += '\n';
    report += join( 'User         : ' + usr,
                    'Home folder  : ' + home,
                    'Start script : ' + shell,
                    'Groups       : ' + join(keys(users[usr]), sep:'\n               '),
                    sep:'\n');
    report += '\n';
  }
  if(!empty_or_null(users[usr]))
    replace_kb_item(name:'Host/Users/' + usr + '/Groups', value:join(keys(users[usr]), sep:'\n'));

}

if(!isnull(users))
  replace_kb_item(name:'Host/Users', value:join(keys(users), sep:'\n'));
if(!isnull(usr_acct_list))
  replace_kb_item(name:'Host/non-service/Users', value:join(usr_acct_list, sep:'\n'));

if(checkuid)
{
  report = strcat(
    '\n-----------[ User Accounts ]-----------\n', report_usr,
    '\n----------[ System Accounts ]----------\n', report_sys, '\n'
    '\n----------[ Domain Accounts ]----------\n', report_dom, '\n'
  );
}

structured_groups.report();
structured_accounts.report();
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
