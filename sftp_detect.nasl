#TRUSTED 0625bbc9d00403689356f73599eb25b4f636d2146262d9431f6f9831707f3a72e79c430f0f7dff3db08becda608db34d83415ca3d1ba75307e84245945595d559dec3f7d41312349e128bdc533846ae36bf5576e24f2d7e849f4fadf49c79b494e899dfe6d358af60fc405a08a551062d89b13d7b1bcbbf90bbde941ca40f3a0b5929d7f0fcd4f0f38b79bab39f4454977f093f969de72595ea85be4afa40474c7c3efa3c0231c628346e41cde422f3fdc78645f6872dfd58fe854f880a25deaa9f7f51992c3012f9730de73996fdae4085dcf5e97915928bf60d12af407eef5e53f0ea5e11369c6cf5b59fb9e78514360662573bd3859986d55e7b6bc0d6ddc60e91d3f3e26864948b0e25f0fc27b9e4f769c7c341461027c3bdab3e43d9a743d437e8f6134a9d93bcedfbd9feb05b2e15092d4fff9e2e4467c1e8ce5cf95c5c937eea78e08ad52f78f7fd8422933ff413895f34ce7a4fb112d90cf14411192ac3a21d259ca34755a3d596d87951a155952cadb33d3be8d026119061ad2158dde8ba95b626bc032f2bf7830cdd2e07293dd7242e73dc76389c585f8288f62129ba2efee4a3ef9fc11963825f68112c6eb0687f0aa403124fe9fd1dff55da0d0a1001eed0eaba465fd0c8fd455db1cd12c18e9e50f1d5120dbcdd97cdc031649213c3d964d93f7c8ade8a82013b75ccc6ddd528c134a7ad5496d98463c4fc4c0
#TRUST-RSA-SHA256 56fcb6bf2503dfb4fb88f8f9db707be1e6e0f3d9ad28a226bd26bd315df0bcd986df269109ab00a842d722481e67e35815125533b3b4dd98466f625b081d3ae5e376a68452413540620f45d81427f226fe2deeefc77e5f7332162319cc6e95f7f86c28c10f0b5370513bed59245c2c3d3126b40f8993e1049e81d7c5efe83f6c50cd68f457c12eb636b7690bca7dc17ececa5d395d6632a73738cc9a39b35edac5073484770d0a82564add8e4ae5ade9ee24b2d057c821f021fbb85eb804e821f32ad31430cadfa9a3046e0279c122dbd4d4779543a68daa7bd7d02c48f2dd41c53a3c8bd23de2a65e6d6f713b56986db565ce4d868ca54a743568840a80780b80117e60bad0d0d479adb69c9e9718376003cc500a4fe2bfe34ad87b59635cf0e7f03b41ee0eba84d08d1dd028c2e7e769075550d5294a66ed49ac261fde58c1c3f2253b6d433173d76eca2884b711b718f75928358a714723cea7bdf34e4be1428d91ed3f5a8ea048be90c93324be76991e4259048eb3a549566226cadec8ec33b7319d29e9120ed0e0302b1d9d2bbb61a65a3e6cdab0b4d8111c83294c6ee8798033470c15517c7fd48e5d8d2128a75e2d0f3eb205c81ea96982e90e33194bb9e864719d0b03068e4766b6212a265ce956831ef5e99df41d93888dc296593d043ec50ad11445f5e6963f8da3f5b7aeec9124f3d4e4fafb83f2962e6189f14a
#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(72663);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_name(english:"SFTP Supported");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service supports SFTP.");
  script_set_attribute(attribute:"description", value:
"The remote SSH service supports the SFTP subsystem. SFTP is a protocol
for generalized file access, file transfer, and file management
functionalities, typically over SSH.

Note that valid credentials are required to determine if SFTP is
supported and also that SFTP support can be enabled selectively for
certain accounts.  Nessus will check each credential supplied in
the current scan policy for SFTP support.  If the scan is not
restricted to supplied logins, it will also try 'guest' and
'anonymous'.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/SSH_File_Transfer_Protocol");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this facility agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_settings.nasl", "ssh_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("ssh_lib.inc");

enable_ssh_wrappers();
port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
report = "";

function check_sftp(session, login)
{
  # Test each account.
  var dir = "/";
  var max_files = 10;

  var sftp_session = session.get_sftp_session();
  if(!sftp_session.init())
    return FALSE;

  set_kb_item(name:"SSH/"+port+"/sftp/login", value:login);

  if (report_verbosity > 0)
  {
    if(report != "")
      report += '\n';

    report = '\n' + 'Nessus was able to access the SFTP service using the following' +
             '\n' + 'account :' +
             '\n' +
             '\n' + '  ' + login;

    var listing = sftp_session.list_directory(dir_path:dir);
    if(!isnull(listing))
    {
      report += '\n' +
                '\n' + 'And it was able to collect the following listing of \'' + dir + '\' :' +
                '\n';
      var i = 0;
      var truncated = FALSE;
      foreach var file(listing)
      {
        report += '\n' + '  ' + file.get_printable_listing();
        i++;
        if(i > max_files)
        {
          truncated = TRUE;
          break;
        }
      }
      if(truncated)
      {
        report += '\n' +
                  '\n' + 'Note that this listing is incomplete and limited to ' + max_files + ' entries.' +
                  '\n';
      }
    }
  }
}

if(supplied_logins_only)
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Generate a list of accounts to check.
i = 0;
logins      = make_array();
passwords   = make_array();
passphrases = make_array();
privs       = make_array();
pubs        = make_array();
certs       = make_array();
realms      = make_array();
kdcs        = make_array();
kdc_ports   = make_array();
kdc_use_tcp = make_array();

# - anonymous
logins[i]    = "anonymous";
passwords[i] = SCRIPT_NAME + '@nessus.org';
i++;

# - guest
logins[i]    = "guest";
passwords[i] = SCRIPT_NAME + '@nessus.org';
i++;

# - credentials supplied in the scan policy.
kb_login = kb_ssh_login();
if (strlen(kb_login))
{
  found = FALSE;
  for (k=0; k<i; k++)
  {
    if (kb_login == logins[k])
    {
      found = TRUE;
      break;
    }
  }
  if (!found)
  {
    logins[i]      = kb_login;
    passwords[i]   = kb_ssh_password();
    passphrases[i] = kb_ssh_passphrase();
    privs[i]       = kb_ssh_privatekey();
    pubs[i]        = kb_ssh_publickey();
    certs[i]       = kb_ssh_certificate();
    realms[i]      = kb_ssh_realm();
    kdcs[i]        = get_kb_item("Secret/SSH/kdc_hostname");
    kdc_ports[i]   = get_kb_item("Secret/SSH/kdc_port");
    kdc_use_tcp[i] = get_kb_item("Kerberos/SSH/kdc_use_tcp");
    i++;
  }
}

for (j=0; TRUE; j++)
{
  idx = sshlib::kb_index(j);
  login = get_kb_item("Secret/SSH" + idx + "login");
  if (isnull(login)) break;
  pass = get_kb_item("Secret/SSH" + idx + "password");

  found = FALSE;
  for (k=0; k<i; k++)
  {
    if (login == logins[k])
    {
      found = TRUE;
      break;
    }
  }

  if(empty_or_null(login))
    break;

  if (!found)
  {
    logins[i] = login;
    passwords[i] = get_kb_item("Secret/SSH" + idx + "password");
    passphrases[i] = get_kb_item("Secret/SSH" + idx + "passphrase");
    privs[i] = kb_ssh_alt_privatekey(j);
    certs[i] = get_kb_item("Secret/SSH" + idx + "/certificate");
    realms[i] = get_kb_item("Kerberos/SSH" + idx + "realm");
    kdcs[i] = get_kb_item("Secret/SSH" + idx + "kdc_hostname");
    kdc_ports[i]   = get_kb_item("Secret/SSH" + idx + "kdc_port");
    kdc_use_tcp[i] = get_kb_item("Kerberos/SSH" + idx + "kdc_use_tcp");
    i++;
  }
}

n = i;

checked_logins = make_list();
working_logins = 0;

for(i = 0; i < n; i++)
{
  append_element(var:checked_logins, value:logins[i]);

  var session = new sshlib::session();
  session.open_connection(port:port);

  var extra = { "username":logins[i],
                "password":passwords[i]  };

  if(realms[i])
  {
    auth_method = "gssapi";
    extra["realm"] = realms[i];
    replace_kb_item(name:"Secret/SSH/kdc_hostname", value:kdcs[i]);
    replace_kb_item(name:"Secret/SSH/kdc_port", value:kdc_ports[i]);
    if(kdc_use_tcp[i])
      replace_kb_item(name:"Kerberos/SSH/kdc_use_tcp", value:TRUE);
    else
      replace_kb_item(name:"Kerberos/SSH/kdc_use_tcp", value:FALSE);
  }
  else if(passwords[i])
  {
    auth_method = "keyboard-interactive";
    if(!session.auth_method_supported(method:auth_method, username:logins[i]))
      auth_method = "password";
  }
  else if(privs[i])
  {
    auth_method = "publickey";
    extra["privatekey"] = privs[i];
    extra["passphrase"] = passphrases[i];
    extra["cert"] = certs[i];
  }
  else
  {
    continue;
  }

  if(session.login(method:auth_method, extra:extra))
  {
    working_logins++;
    check_sftp(session:session, login:logins[i]);
  }

  session.close_connection();

  if(auth_method == "gssapi")
  {
    rm_kb_item(name:"Secret/SSH/kdc_hostname");
    rm_kb_item(name:"Secret/SSH/kdc_port");
    rm_kb_item(name:"Kerberos/SSH/kdc_use_tcp");
  }
}

if(working_logins == 0)
{
  err_msg = "The SSH service listening on port "+port+" does not support SFTP access for the login";
  if (max_index(checked_logins) > 1) err_msg += "s";
  err_msg += " '" + join(checked_logins, sep:"' / '") + "'.";
  exit(0, err_msg);
}

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
