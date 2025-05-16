#TRUSTED 02b406f349920a367055a8866eaf34679dbc680f29dd6959534e7eccea8f77e510af84a1e2ebae1b7d263a6b909f474ee11af879f213ea284d79836e123708067be80ff7ca19a3cdb607a0ebc0262341a30d70d64d85c1aeca7052f4950f27ed2131ef4e3b62969016ef0d8cdea8150a65d80fe8b6d1155f566cff8eba3b2112b417d751fc5f6270e85451c8ba333cd2a9c60a15349c9f946e74ebd42301151b4dc9ce5256d858a2ef294806f7551609e83e75d8f70fbd1ec7c8b7c4e3b3ed0838c71ba265d90ffea84b006d3d9b1e57a7904c7030938b67c9dec7b19c959032d0da17f4f0f3f0f487bcb3d88a3e148de46055ac41957013bd6d1d23ef6ddf53930c168501ddf9c51dde293b192ed992d55a56f1e38ed2eeb8389b590388765f1c76c93216737822d6d473fa0775b3ec3f51c19dc63e1ed12adf96071e5198190d63c1c42aa13c97faad1cf6c226aa7bb34eef1d21df787bb2c6032713243f6ce1b0a33981ff06ec0db25ae753d27bab19879b58041ab9fa91f4db7e91135a2bac3fe5e387f7f0efc7293edc567eaf6e1ce876300b6cf04682b16be6bb3daa25cbed97d9da934409f53853f1a632912c9d07d24d93ac58d4a332fcaa03f3066fabb90f14f4c0cf8e2bce10e574457102ab54e1aa4eba0a5b43c1f7cfb312db5bed1f704074132a525e96a4d2b29666ad529ed45a0dcdaf707619ca5ce0427e4c
#TRUST-RSA-SHA256 b302939a0031df0103c94afdc087a4f466dbf33b56114d7d989f6c7cb3bd589405f13c8a2a163d2feb004cb58bceef4ad0aa6adad1fa6b4d46e1db621dd0a281f9b289719f59476d190708e4410640c37e5113f9722e9769593158762fff399e5842f9901b57de4154220220d763b1e1a87821ba465ee645dbad360407fd9bd4ca66fdd74f1c082e7f7d65ac5facd3b5305ba68c8eef1abaab7ef064be9d4fa4afc489d243ca257da3b0c773ebd0ebf88a19c09dd5266937cb503a4027962cff3f9266221e3aefe55d587cf84309828746394f78ffd5602a2bbcb17ad4ee7496140ae796f2d13a31710945d8326c6e5fb6cc336b185b3e4c7e1b1ccccb708a56a2da9ea10b28da94c880fb256bc29f0620f9b65a6c5675782d92da5834e6a9576cf27b62e0d3208469a8a23d7359654e6c89fbb705f4fc80de14046f092a7c6c004ff1ee2639504aa23f64d343d59f6ed209addef58614a08b860918e35691292c99df89ea6e104498e8b3f730952bf4bee56af74053ca6c4c1aed6dc2c201cd32d9a07fd0f5c12841921458ac25113056ba7222d171f7c636e4ae28afeedd106155fd6890095a1dcec17cd06f240f9537fa1d596f6e9c740aade60caf4952208ed29577d5617857c3191781a62e6eb48a0a081de50eb38cde7b74c2ffa99c3a0520362fe651639c1fee25329ec98d9a3553fd530b23dbc753dcfb7a08ef69f4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10394);
  script_version("1.176");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_name(english:"Microsoft Windows SMB Log In Possible");
  script_summary(english:"Attempts to log into the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to log into the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Microsoft Windows operating system or
Samba, a CIFS/SMB server for Unix. It was possible to log into it
using one of the following accounts :

- Guest account
- Supplied credentials");
  # https://support.microsoft.com/en-us/help/143474/restricting-information-available-to-anonymous-logon-users
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c2589f6");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/246261");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2000-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_start_server_svc.nbin", "global_settings.nasl", "kerberos.nasl", "netbios_name_get.nasl", "cifs445.nasl", "logins.nasl", "smb_nativelanman.nasl");
  script_require_keys("SMB/name", "SMB/transport");
  script_require_ports(139, 445, "/tmp/settings");

  exit(0);
}

include("smb_func.inc");
include("lcx.inc");
include("structured_data.inc");


# Plugin is run by the local Windows Nessus Agent
if (get_kb_item("nessus/product/agent"))
{
  # Note: some Windows credentialed plugins call:
  # script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  # Here we manually set the KBs
  set_kb_item(name:"SMB/login", value:"");
  set_kb_item(name:"SMB/password", value:"");

  # Set Local checks KB items
  set_kb_item(name:"Host/windows_local_checks", value:TRUE);
  set_kb_item(name:"Host/local_checks_enabled", value:TRUE);
  replace_kb_item(name:'debug/Host/local_checks_enabled_source/plugins/Windows/s/smb_login.nasl', value: 68);

  # set domain/workgroup if known
  # set_kb_item(name:"SMB/domain", value:"");
  exit(0);
}

global_var session_is_admin, port;

##
# kdc will only be present for credentials where the user has
# specified kerberos authentication on scanners >= nessus 6.0
##
function login(lg, pw, dom, lm, ntlm, kdc)
{
  local_var r, r2, soc;

  session_is_admin = 0;

  if (kdc)
  {
    replace_kb_item(name:"Kerberos/SMB/kdc_use_tcp", value:kdc["use_tcp"]);
    replace_kb_item(name:"SMB/only_use_kerberos", value:TRUE);
    replace_kb_item(name:"KerberosAuth/enabled", value:TRUE);
    # used by open_sock_ex() (nessus >= 6)
    replace_kb_item(name:"Secret/SMB/kdc_hostname", value:kdc["host"]);
    replace_kb_item(name:"Secret/SMB/kdc_port", value:int(kdc["port"]));
    # used by open_sock_kdc() (nessus < 6)
    replace_kb_item(name:"Secret/kdc_hostname", value:kdc["host"]);
    replace_kb_item(name:"Secret/kdc_port", value:int(kdc["port"]));
    replace_kb_item(name:"Secret/kdc_use_tcp", value:int(kdc["use_tcp"]));
  }
  # Use latest version of SMB that Nessus and host share (likely SMB 2.002)
  if (!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
  r = NetUseAdd(login:lg, password:pw, domain:dom, lm_hash:lm, ntlm_hash:ntlm, share:"IPC$");
  if (r == 1)
  {
    NetUseDel(close:FALSE);
    r2 = NetUseAdd(share:"ADMIN$");
    if (r2 == 1) session_is_admin = TRUE;
  }
  NetUseDel();

  # If that fails, fallback to SMB1
  if (r != 1)
  {
    if (!smb_session_init(smb2:FALSE)) audit(AUDIT_FN_FAIL, 'smb_session_init');
    r = NetUseAdd(login:lg, password:pw, domain:dom, lm_hash:lm, ntlm_hash:ntlm, share:"IPC$");
    if (r == 1)
    {
      NetUseDel(close:FALSE);
      r2 = NetUseAdd(share:"ADMIN$");
      if (r2 == 1) session_is_admin = TRUE;
    }
    NetUseDel();
  }

  if (kdc)
  {
    # this needs to be deleted after each authentication attempt to avoid having stale KDC data in the KB
    # (e.g. 1st credentials attempt kerberos auth, 2nd credentials do not attempt kerberos auth).
    # if kerberos auth succeeds, this data will be saved in the KB permanently below where SMB/login et al are saved
    rm_kb_item(name:"Kerberos/SMB/kdc_use_tcp");
    rm_kb_item(name:"SMB/only_use_kerberos");
    rm_kb_item(name:"KerberosAuth/enabled");
    rm_kb_item(name:"Secret/SMB/kdc_hostname");
    rm_kb_item(name:"Secret/SMB/kdc_post");
    rm_kb_item(name:"Secret/kdc_hostname");
    rm_kb_item(name:"Secret/kdc_port");
    rm_kb_item(name:"Secret/kdc_use_tcp");
  }

  if (r == 1)
  {
    if (session_is_admin) replace_kb_item(name:"SMB/use_smb2", value:session_is_smb2());
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

var login_has_been_supplied = 0;
port = kb_smb_transport();
var name = kb_smb_name();

# the port scanner ran and determined the SMB transport port isn't open
if (get_kb_item("Host/scanned") && !get_port_state(port))
{
  audit(AUDIT_PORT_CLOSED, port);
}

var soc = open_sock_tcp(port);
if (!soc)
{
  audit(AUDIT_SOCK_FAIL, port);
}
close(soc);

##
# Get all of the required parameters from the kb and
# set them to an array for access.
##
var l, p, d, t;
var cred_type, kdc_host, kdc_port, kdc_use_tcp, kdc_info;
var logins, passwords, domains, password_types, cred_types;

for (var i = 0; TRUE; i ++)
{
  l = get_kb_item("SMB/login_filled/" + i);
  if (l)
  {
    l = ereg_replace(pattern:"([^ ]*) *$", string:l, replace:"\1");
  }

  p = get_kb_item("SMB/password_filled/" + i);
  if (p)
  {
    p = ereg_replace(pattern:"([^ ]*) *$", string:p, replace:"\1");
  }
  else
  {
    p = "";
  }

  d = get_kb_item("SMB/domain_filled/" + i);
  if (d)
  {
    d = ereg_replace(pattern:"([^ ]*) *$", string:d, replace:"\1");
  }

  t = get_kb_item("SMB/password_type_filled/" + i);

  cred_type = get_kb_item("SMB/cred_type/" + i);

  if (!get_kb_item("Kerberos/global"))
  {
    kdc_host = get_kb_item("SMB/kdc_hostname_filled/" + i);
    kdc_port = get_kb_item("SMB/kdc_port_filled/" + i);
    kdc_use_tcp = get_kb_item("SMB/kdc_use_tcp_filled/" + i);
  }

  if (l)
  {
    login_has_been_supplied ++;
    logins[i] = l;
    passwords[i] = p;
    domains[i] = d;
    password_types[i] = t;
    cred_types[i] = cred_type;
    if (kdc_host && kdc_port)
    {
      kdc_info[i] = make_array(
        "host", kdc_host,
        "port", int(kdc_port),
        "use_tcp", kdc_use_tcp
      );
    }
  }
  else break;
}

var smb_domain = string(get_kb_item("SMB/workgroup"));

if (smb_domain)
{
  smb_domain = ereg_replace(pattern:"([^ ]*) *$", string:smb_domain, replace:"\1");
}

##
# Start testing access levels for SMB service
##
var hole = 0;
var rand_lg = rand_str(length:8, charset:"abcdefghijklmnopqrstuvwxyz");
var rand_pw = rand_str(length:8);

# Test Null sessions
var null_session;
if (login(lg:NULL, pw:NULL, dom:NULL))
{
  null_session = TRUE;
}
else
  null_session = FALSE;

# Test administrator Null Login
var admin_no_pw, any_login;
if (!supplied_logins_only)
{
  if (login(lg:"administrator", pw:NULL, dom:NULL) && !session_is_guest())
  {
    admin_no_pw = TRUE;
  }
  else
  {
    admin_no_pw = FALSE;
  }

  # Test open to anyone login settings
  if (login(lg:rand_lg, pw:rand_pw, dom:NULL))
  {
    any_login = TRUE;
    set_kb_item(name:"SMB/any_login", value:TRUE);
  }
  else
  {
    any_login = FALSE;
  }
}

##
# Start testing supplied creds
##
var supplied_login_is_correct = FALSE;
var working_login = NULL;
var working_password = NULL;
var working_password_type = NULL;
var working_kdc = NULL;
var working_domain = NULL;
var working_cred_type = NULL;
var login_cred_type = NULL;

var valid_logins = make_list();
var valid_passwords = make_list();
var logged_in, user_login, user_password, k_password, user_domain, p_type, kdc;
var lm, ntlm, thisUser;

var loginFails = make_nested_array(); # for reporting failed login attempts

for (i = 0; logins[i] && !supplied_login_is_correct; i++)
{
  logged_in = 0;
  user_login = logins[i];
  k_password = user_password = passwords[i];
  user_domain = domains[i];
  p_type = password_types[i];
  kdc = kdc_info[i];

  if (p_type == 0)
  {
    lm = ntlm = NULL;
  }
  if (p_type == 1)
  {
    lm = hex2raw2(s:tolower(user_password));
    ntlm = user_password = NULL;
  }
  else if (p_type == 2)
  {
    ntlm = hex2raw2(s:tolower(user_password));
    lm = user_password = NULL;
  }

  # user domain
  if (login(lg:user_login, pw:user_password, dom:user_domain, lm:lm, ntlm:ntlm, kdc:kdc) && !session_is_guest())
  {
    logged_in ++;
    if (session_is_admin) supplied_login_is_correct = TRUE;
    if (!working_login || session_is_admin)
    {
      working_login = user_login;
      if (isnull(user_password))
      {
        if (!isnull(lm)) user_password = hexstr(lm);
        else if (!isnull(ntlm)) user_password = hexstr(ntlm);
      }

      working_password = user_password;
      working_password_type = p_type;
      working_kdc = kdc;
      working_domain = user_domain;
      working_cred_type = cred_types[i];
    }
  }
  else
  {
    if (tolower(user_domain) != tolower(smb_domain))
    {
      # smb domain
      if (login(lg:user_login, pw:user_password, dom:smb_domain, lm:lm, ntlm:ntlm, kdc:kdc) && !session_is_guest())
      {
        logged_in ++;
        if (session_is_admin) supplied_login_is_correct = TRUE;
        if (!working_login || session_is_admin)
        {
          working_login = user_login;
          if (isnull(user_password))
          {
            if (!isnull(lm)) user_password = hexstr(lm);
            else if (!isnull(ntlm)) user_password = hexstr(ntlm);
          }
          working_password = user_password;
          working_password_type = p_type;
          working_domain = smb_domain;
          working_cred_type = cred_types[i];
        }
      }
    }

    if (!logged_in)
    {
      # no domain
      if (login(lg:user_login, pw:user_password, dom:NULL, lm:lm, ntlm:ntlm, kdc:kdc) && !session_is_guest())
      {
        logged_in++;
        if (session_is_admin) supplied_login_is_correct = TRUE;
        if (!working_login || session_is_admin)
        {
          working_login = user_login;
          if (isnull(user_password))
          {
            if (!isnull(lm)) user_password = hexstr(lm);
            else if (!isnull(ntlm)) user_password = hexstr(ntlm);
          }
          working_password = user_password;
          working_password_type = p_type;
          working_domain = NULL;
          working_cred_type = cred_types[i];
        }
        smb_domain = NULL;
      }
    }

    if (!logged_in)
    {
      thisUser = '';
      if (!empty_or_null(user_domain))
        thisUser += user_domain + '\\';
      thisUser += user_login;

      if (!empty(thisUser))
        loginFails[thisUser] = 'Failed to authenticate using the supplied credentials.';
    }
  }
}

var user_password_type, user_kdc;

var sd_auth_info = new("structured_data_authentication_status_information");

if (working_login)
{
  supplied_login_is_correct = TRUE;
  user_login = working_login;
  user_password = working_password;
  user_password_type = working_password_type;
  user_kdc = working_kdc;
  smb_domain = working_domain;
  login_cred_type = working_cred_type;

  replace_kb_item(name:"Host/Auth/SMB/"+port+"/Success", value:working_login);
  rm_kb_item(name:"Host/Auth/SMB/"+port+"/"+SCRIPT_NAME+"/Problem");
  rm_kb_item(name:"Host/Auth/SMB/"+port+"/Failure");
  lcx::log_auth_success(proto:lcx::PROTO_SMB, port:port, user:user_login, clear_failures:TRUE);  


  sd_auth_info.insert_auth_status(auth_type:"SMB", user_id:user_login, method:login_cred_type, status:sd_auth_info.SUCCESS);

  foreach var username (keys(loginFails))
  {
    # Right now we only count the number of failed logins, if we ever send the failed login up we will
    # need to assess if we need to supply the method as well.
    sd_auth_info.insert_auth_status(auth_type:"SMB", user_id:username, method:"N/A", status:sd_auth_info.FAILED);
  }

}
else
{
  var kb_pre = "Host/Auth/SMB/"+port;
  set_kb_item(name:kb_pre+"/Failure", value:TRUE);
  foreach var username (keys(loginFails))
  {
    lcx::log_issue(type:lcx::ISSUES_AUTH, msg:loginFails[username],
      port:port, proto:lcx::PROTO_SMB, user:username);

    # Right now we only count the number of failed logins, if we ever send the failed login up we will
    # need to assess if we need to supply the method as well.
    sd_auth_info.insert_auth_status(auth_type:"SMB", user_id:username, method:"N/A", status:sd_auth_info.FAILED);
  }
  if (!supplied_login_is_correct && !admin_no_pw && login_has_been_supplied)
    lcx::log_issue(type:lcx::ISSUES_SVC, proto:lcx::PROTO_SMB, msg:
      'It was not possible to log into the remote host via smb ' +
      '(invalid credentials).', port:port);
}

sd_auth_info.report_internal();

var report = '';

if (null_session || supplied_login_is_correct || admin_no_pw || any_login)
{
  if (supplied_login_is_correct)
  {
    if (!user_password) user_password = "";

    set_kb_item(name:"SMB/login", value:user_login);
    set_kb_item(name:"SMB/password", value:user_password);
    set_kb_item(name:"SMB/password_type", value:user_password_type);
    if (!isnull(user_kdc))
    {
      replace_kb_item(name:"Secret/SMB/kdc_hostname",  value:user_kdc["host"]);
      replace_kb_item(name:"Secret/SMB/kdc_port",      value:int(user_kdc["port"]));
      replace_kb_item(name:"Secret/kdc_hostname",      value:kdc["host"]);
      replace_kb_item(name:"Secret/kdc_port",          value:int(kdc["port"]));
      replace_kb_item(name:"Secret/kdc_use_tcp",       value:int(kdc["use_tcp"]));
      replace_kb_item(name:"Kerberos/SMB/kdc_use_tcp", value:user_kdc["use_tcp"]);
      replace_kb_item(name:"KerberosAuth/enabled",     value:TRUE);
      replace_kb_item(name:"SMB/only_use_kerberos",    value:TRUE);
    }
    if (smb_domain != NULL)
    {
      set_kb_item(name:"SMB/domain", value:smb_domain);
      report += '- The SMB tests will be done as ' + smb_domain + '\\' + user_login + '/******\n';
    }
    else
      report += '- The SMB tests will be done as ' + user_login + '/******\n';

    if(session_is_admin)
      replace_kb_item(name:"Host/Auth/SMB/" + port + "/MaxPrivs", value:1);
  }

  # https://discussions.nessus.org/message/9562#9562 -- Apple's Time Capsule accepts any login with a
  # blank password
  if (admin_no_pw && !any_login && !login(lg:rand_str(length:8), pw:""))
  {
    set_kb_item(name:"SMB/blank_admin_password", value:TRUE);
    report += '- The \'administrator\' account has no password set.\n';
    hole = 1;
    if (!supplied_login_is_correct)
    {
      set_kb_item(name:"SMB/login", value:"administrator");
      set_kb_item(name:"SMB/password", value:"");
      set_kb_item(name:"SMB/domain", value:"");
    }
  }

  if (any_login)
  {
    set_kb_item(name:"SMB/guest_enabled", value:TRUE);
    report += '- Remote users are authenticated as \'Guest\'.\n';
    if (!supplied_login_is_correct && !admin_no_pw)
    {
      set_kb_item(name:"SMB/login", value:rand_lg);
      set_kb_item(name:"SMB/password", value:rand_pw);
      set_kb_item(name:"SMB/domain", value:"");
    }
  }

  if (null_session)
  {
    set_kb_item(name:"SMB/null_session_suspected", value:TRUE);
    if (report_paranoia >= 2 || !empty_or_null(report))
    {
      report += '- NULL sessions may be enabled on the remote host.\n';
    }
    if (!supplied_login_is_correct && !admin_no_pw && !any_login)
    {
      set_kb_item(name:"SMB/login", value:"");
      set_kb_item(name:"SMB/password", value:"");
      set_kb_item(name:"SMB/domain", value:"");
    }
  }

  if (supplied_login_is_correct || admin_no_pw)
  {
    if (!get_kb_item("SMB/not_windows"))
    {
      set_kb_item(name:"Host/windows_local_checks", value:TRUE);
      set_kb_item(name:"Host/local_checks_enabled", value:TRUE);
      replace_kb_item(name:'debug/Host/local_checks_enabled_source/plugins/Windows/s/smb_login.nasl', value: 538);
    }

    var kb_dom = get_kb_item("SMB/domain");
    var kb_lg  = get_kb_item("SMB/login");
    if (isnull(kb_dom)) kb_dom = get_host_ip();
    var login_used = kb_dom + '\\' + kb_lg;

    set_kb_item(name:"HostLevelChecks/smb_login", value:login_used);
    if (!empty_or_null(login_cred_type))
    {
      replace_kb_item(name:"HostLevelChecks/cred_type", value:login_cred_type);
    }
    
    if (defined_func("report_xml_tag"))
    {
      report_xml_tag(tag:"local-checks-proto", value:"smb");
      report_xml_tag(tag:"smb-login-used",     value:login_used);
    }
  }

  if (supplied_login_is_correct || admin_no_pw || any_login || (null_session && (report_paranoia >= 2)))
  {
    security_note(port:port, extra:report);
  }
  else
  {
    audit(AUDIT_POTENTIAL_VULN, 'scanner was able to connect to a share with no username or password, but did not 
    attempt to bind. A NULL session may be possible but this');
    # The scanner was able to connect to a share with no username or password, but did not attempt to bind. A NULL 
    # session may be possible but this install is potentially affected and therefore is only reported if 
    # 'Report Paranoia' is set to 'Paranoid'.
  }
}
else
{
  if (isnull(get_kb_item('SMB/login_filled/0'))) audit(AUDIT_MISSING_CREDENTIALS, "Windows");
  else exit(0, "Failed to connect to the SMB service. Could not authenticate with the supplied credentials.");
}
