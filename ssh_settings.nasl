#TRUSTED a9165c8d42b9dd92d56c5a3fe4c49393a9a838ae5684f21c8f6b9132acd9e8830f97c2ac4f06b2936c92b74583247225f643f3e8eb8f89796b57e7f896a8609debfa5a8235708c405f61c3a834b97c762e0f3e737f5bda7e55b7670a87655f90a06902f8d364da2ec3fdd0974f9419ce0c102a389f1fa0185437e03db876bb16be3f0a90753315cc0df34ea9d75c14cda57763e74d0a9632ee20efc6e4a0f0895b18f03edccfe9e127819741782c9eafe3d6311d57d7e894d939b843b8d350df1b6b098ca01e478335911c38a5c10153684510c0c51f0a4860040c18c294826b76b53239d08a2679234020c8aa364b0d0469aef30a2514089e48c1c25b062215271b022a1e912d41b768739836fc8e877bb661a8d1ed0d409094989ed4106b841b0b3148b98195e4ba7c340aea87b214da90c5727a2c0574c52295e288d4063ecd29ea0b3b00240c48a5dcf7f311839a917373959bfce5132b088564375f18035465353aeb3f63657383dcc2dbb95a9c92cced23e94a408fbd520c7ceec556d45e00173f4cc301976e06a61da2e095a44774895faeb7bdb38f43b43cb9f9edd7c83b027704af3eac23549985d7b868b92c71c20e216d6abaecdc8e6625762cfa09fda20d8a96536f5ca147f980789848a0f7b76988a62166e4367ff567ba92958b716dd808aa320045cbcb97cce8b6bd8e5b5b3f41014ae15ecaf70d8e19eee2
#TRUST-RSA-SHA256 65cc04a673eea94fac954a011137e3870875aa1aaadb9587b0b4694c6db32bfa5123c97a28b0cd07c2a64cb5e4a0dca173a8365e139f0cedf9b17cc8abb789be618721fcc5805d68374f11637b404dda8d51ac41a42e7ff67877d8d5b909e8f093331f3c04a87aa5b25710c56b6d83d659d29e7b37194d18ee5ec92912219a03e4f8392e6967b01e46867344fcdd69d1cdcb517e7c68a288ff19f3a2718139b4a9a9398181b7686cbff567f24b2a3ed12bef7a26d4c064ea9bc6d44550fa9b5c022897c7b3941acd7c46e487a97f84eb31ab748483a650cf83fcd547af84b1b0e8ce41eec11077fb84777a44a0e6c504e5adcac2f171cab66cb3c82f5ddacc7c575408321c5a7b7860c6b8d238064f8a273ac41fb33036aa3707bb60a2e6c614a0358ae16e9fbf754ff14346b3fb7984b8b02c9b6509d489625f2a28b8e90501b4277de10a19fbe449f456fb3ab54a40822a2c44c9c545d03df5c975997911d152670abb6450e5065ae000f8fe09a39498fc73bde5d43a27cad6a2e9e414981f217800dd0dc4e99907fe677d9c9614dcc67ae2f43ad0fbc4763bf532a12b473912c2a9389d499a4aabb7c12f5145ae48f516e0839edf7a304745bf6fcd235b8b88ad594a0fcfca93ed6d4d4aa728fc8ddc7aa3f7a63c009ff8e64a5c6a38e0f1ecd60c78156412655d2007e24de0649163035ec07d7acc93210e1fdd1b3f50e9

#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
  script_id(14273);
  script_version("1.138");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_name(english:"SSH settings");
  script_summary(english:"Set SSH keys & user name to perform local security checks.");

  script_set_attribute(attribute:"synopsis", value:
  "This plugin configures the SSH subsystem.");
  script_set_attribute(attribute:"description", value:
  "This plugin initializes the SSH credentials as set by the user.

  To set the credentials, edit your scan policy and go to the section
  'Credentials'.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/15");

  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_end_attributes();

  script_family(english:"Settings");

  script_dependencies("datapower_settings.nasl");

  script_category(ACT_SETTINGS);

  script_copyright(english:"This script is Copyright (C) 2004-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("global_settings.nasl", "pam_ssh_auto_collect.nbin", "ping_host.nasl");

  if (defined_func("bn_random"))
  {
    script_add_preference(
      name  : "SSH user name : ",
      type  : "entry",
      value : "root"
    );
    script_add_preference(
      name  : "SSH password (unsafe!) : ",
      type  : "password",
      value : ""
    );
    script_add_preference(
      name  : "SSH public key to use : ",
      type  : "file",
      value : ""
    );
    script_add_preference(
      name  : "SSH private key to use : ",
      type  : "file",
      value : ""
    );
    script_add_preference(
      name  : "Passphrase for SSH key : ",
      type  : "password",
      value : ""
    );
    script_add_preference(
      name  : "Elevate privileges with : ",
      type  : "radio",
      value : "Nothing;sudo;su;su+sudo;dzdo;pbrun;Cisco 'enable'"
    );
    script_add_preference(
      name  : "Privilege elevation binary path (directory) : ",
      type  : "entry",
      value : ""
    );
    script_add_preference(
      name  : "su login : ",
      type  : "entry",
      value : ""
    );
    script_add_preference(
      name  : "Escalation account : ",
      type  : "entry",
      value : "root"
    );
    script_add_preference(
      name  : "Escalation password : ",
      type  : "password",
      value : ""
    );
    script_add_preference(
      name  : "SSH known_hosts file : ",
      type  : "file",
      value : ""
    );
    script_add_preference(
      name  : "Preferred SSH port : ",
      type  : "entry",
      value : "22"
    );
    script_add_preference(
      name  : "Client version : ",
      type  : "entry",
      value : "OpenSSH_5.0"
    );

    for (var i = 1; i <= 5; i++)
    {
      script_add_preference(
        name  : "Additional SSH user name (" + i + ") : ",
        type  : "entry",
        value : ""
      );
      script_add_preference(
        name  : "Additional SSH password (" + i + ") : ",
        type  : "password",
        value : ""
      );
    }

    script_exclude_keys("Host/ping_failed", "Host/dead");
  }

  exit(0);
}

include("http.inc");
include("ssl_funcs.inc");
include("cyberark.inc");
include("cyberarkrest.inc");
include("beyondtrust.inc");
include("lieberman.inc");
include("hashicorp.inc");
include("arcon.inc");
include("ssh_func.inc");
include("thycotic.inc");
include("centrify.inc");
include("wallix.inc");
include("delinea.inc");
include("senhasegura.inc");
include("qianxin.inc");
include("fudo.inc");
include("debug.inc");

dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'SSH Settings Plugin Loaded');

enable_ssh_wrappers();

##
# Determines if the given hostname patterns match the current target
#
# The man page for sshd(8) says:
#
# "Hostnames is a comma-separated list of patterns (`*' and `?' act as
#  wildcards); each pattern in turn is matched against the canonical host
#  name (when authenticating a client) or against the user-supplied name
#  (when authenticating a server).  A pattern may also be preceded by `!' to
#  indicate negation: if the host name matches a negated pattern, it is not
#  accepted (by that line) even if it matched another pattern on the line.
#  A hostname or address may optionally be enclosed within `[' and `]'
#  brackets then followed by `:' and a non-standard port number"
#
# @anonparam [patterns:string] a comma delimited list of patterns
#
# @return [boolean] TRUE if the IP or hostname of the current target matches any patterns,
#                   FALSE otherwise
##
function patterns_match_this_host()
{
  var patterns = split(_FCT_ANON_ARGS[0], sep:',', keep:FALSE);

  var port = _FCT_ANON_ARGS[1];
  if (isnull(port))
    port = 22;

  var match = FALSE;
  var target_ip = get_host_ip();
  var target_hostname = get_host_name();
  var negated;

  for (var pattern of patterns)
  {
    negated = FALSE;
    if (pattern[0] == '!')
    {
      negated = TRUE;
      pattern = substr(pattern, 1);
    }

    # key with non-standard port, e.g., [ssh.example.net]:2222
    if (pattern =~ "^\[.*\]:[0-9]+")
    {
      if (pattern == '[' + target_ip + ']:' + port || pattern == '[' + target_hostname + ']:' + port)
      {
        # a negated pattern takes precedence over all other patterns
        if (negated)
          return FALSE;
        match = TRUE;
      }
    }
    else
    {
      pattern = str_replace(string:pattern, find:'.', replace:"\.");
      pattern = str_replace(string:pattern, find:'*', replace:".*");
      pattern = str_replace(string:pattern, find:'?', replace:".");
      pattern = '^' + pattern + '$';

      if (preg(string:target_ip, pattern:pattern) || preg(string:target_hostname, pattern:pattern, icase:TRUE))
      {
        # a negated pattern takes precedence over all other patterns
        if (negated)
          return FALSE;
        match = TRUE;
      }
    }
  }

  return match;
}

##
# Gather ssh settings from the UI and store them in the kb for access
#
# @return list of the ssh creds
##
function ssh_settings_get_settings()
{
  var jindex, ssh_prefix, ssh_postfix, ssh_pub_key_cert, ssh_pw_warning;
  var auth_type, account, private_key, passphrase, password;
  var kdc, kdc_port, kdc_transport, realm;
  var sudo, su_login, sudo_path, root, sudo_password, cert, custom_prompt;
  var result_array, target_priority_list;

  var beyond_creds, lieberman_creds, cyberark_result, ca_result, thycotic_result, centrify_result;
  var hashicorp_result, arcon_result, wallix_result, delinea_result, senha_result, qax_result, fudo_result;
  var domain, pam, kb_path, object, safe, address;

  ###
  ## Begin global preferences
  ###
  var EsclPwdType = "sudo";
  var client_ver  = script_get_preference("Client version : ");
  var pref_port = script_get_preference("Preferred SSH port : ");
  var least_priv = script_get_preference("attempt_least_privilege");
  var auto_accept = get_kb_item('Settings/automatically_accept_disclaimer');
  var result_list = [];

  dbg::detailed_log(
    lvl:1,
    src:FUNCTION_NAME,
    msg:'SSH Settings Initializing.',
    msg_details: {
      'Client Version': {lvl:1, value:client_ver},
      'Port': {lvl:1, value:pref_port},
      'Least Priv': {lvl:1, value:least_priv},
      'Auto-accept disclaimers': {lvl:1, value:auto_accept}
    }
  );

  ##
  # j is used to keep track of the current successfully gathered creds to
  # insert into the kb. The kb needs to be inserted starting with no counter
  # and increase in numerical order string at 0 and not skipping any values.
  # kb first  /SSH/value/test = X
  # kb second /SSH/value/0/test = X
  # kb third  /SSH/value/1/test = X
  ##
  var j = 0;

  ##
  # Loop through all credentials and store the values in an array
  # to be indexed later for scan storage.
  # The array is used instead of direct insert to be able to easily
  # access the values for any normalization or generic manipulation.
  ##
  for (var i=0; i < 1000; i++)
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'SSH Settings Credential Loop '+i);

    if (i > 0)
    {
      ssh_prefix = "Additional "; # additional creds add the "Additional" prefix
      ssh_postfix = " ("+i+") : "; # additional creds are followed by an index value

      # The additional instances of the public key/cert will use
      # a different string parameter displayed here.
      ssh_pub_key_cert = "Additional SSH certificate to use ("+i+") : ";

      # additional passwords do not have the unsafe warning
      ssh_pw_warning =  "";
    }
    else
    {
      ssh_prefix = ""; # first instance does not have a prefix
      ssh_postfix = " : "; # there is no index into the first instance of parameters

      # The first instance of the public key/cert will use
      # a different string parameter displayed here.
      ssh_pub_key_cert = "SSH public key to use : ";

      # The first instance of the password field has the unsafe title
      ssh_pw_warning =  " (unsafe!)";
    }

    if (j > 0)
    {
      # create the index value to be stored in the KB. The value is j-1 because we start
      # counting kb index values at 0.
      jindex = "/"+(j-1)+"/"; # define the index value into the KB
    }
    else
    {
      # The first index value will always be stored without an int index
      jindex = "/"; # define no index into the KB
    }

    # Get password type or username. Break if none supplied.
    auth_type = script_get_preference(ssh_prefix+"SSH password type"+ssh_postfix);
    account =  script_get_preference(ssh_prefix+"SSH user name"+ssh_postfix);
    account = string(account);

    if(isnull(auth_type) && strlen(account) < 1)
    {
      if (COMMAND_LINE)
        break;
      if ( i <= 5 )
        continue;
      else
        break;
    }
    else
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Password Type :'+ auth_type);
    }

    cert = script_get_preference_file_content(ssh_pub_key_cert);
    private_key = script_get_preference_file_content(ssh_prefix+"SSH private key to use"+ssh_postfix);
    passphrase  = script_get_preference(ssh_prefix+"Passphrase for SSH key"+ssh_postfix);
    password = script_get_preference(ssh_prefix+"SSH password"+ssh_pw_warning+ssh_postfix);
    custom_prompt = script_get_preference(ssh_prefix+"SSH custom password prompt"+ssh_postfix);
    target_priority_list = script_get_preference(ssh_prefix+"Targets to prioritize credentials"+ssh_postfix);
    kdc = script_get_preference(ssh_prefix+"Kerberos KDC"+ssh_postfix);
    kdc_port = script_get_preference(ssh_prefix+"Kerberos KDC Port"+ssh_postfix);
    kdc_transport = script_get_preference(ssh_prefix+"Kerberos KDC Transport"+ssh_postfix);
    realm = script_get_preference(ssh_prefix+"Kerberos Realm"+ssh_postfix);

    # For additional elevate priv only attempt to read the new privilege elevation preferences when running at Nessus 6 compatibility or later.
    # on scanners running at older than Nessus 6 compatibility, the values read from the original privilege elevation preferences above will be reused
    # a policy is using the new Nessus 6 preferences if the following one is present
    if (script_get_preference(ssh_prefix+"Elevate privileges with"+ssh_postfix))
    {
      sudo = script_get_preference(ssh_prefix+"Elevate privileges with"+ssh_postfix);
      su_login = script_get_preference(ssh_prefix+"su login"+ssh_postfix);
      sudo_path = script_get_preference(ssh_prefix+"Privilege elevation binary path (directory)"+ssh_postfix);
      root = script_get_preference(ssh_prefix+"Escalation account"+ssh_postfix);

      if (root !~ "^[A-Za-z][A-Za-z0-9_.-]+$")
      {
        root = "root";
      }

      sudo_password = script_get_preference(ssh_prefix+"Escalation password"+ssh_postfix);
    }
    #
    # Gather beyondtrust creds
    #
    if ("BeyondTrust" >< auth_type || script_get_preference(ssh_prefix+"SSH BeyondTrust Host"+ssh_postfix))
    {
      beyond_creds = beyondtrust::get_password(login:account, prefix:ssh_prefix + "SSH ", postfix:ssh_postfix);
      if(beyond_creds.success)
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Successfully retrieved BeyondTrust PAM SSH credentials.");
        if (beyond_creds.privatekey)
        {
          private_key = beyond_creds.privatekey;
          passphrase = beyond_creds.body;
        }
        else
        {
          password = beyond_creds.body;
        }
        if (beyond_creds.elevation_command)
        {
          # currently password safe will only ever list
          # "sudo", "pbrun", or "pmrun" as the elevation command
          if (beyond_creds.elevation_command == "sudo")
          {
            sudo = "sudo";
          }
          else if (beyond_creds.elevation_command == "pbrun")
          {
            sudo = "pbrun";
          }
          else
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:
              "unsupported elevation command: " + beyond_creds.elevation_command);
          }

          if (beyond_creds.privatekey)
          {
            sudo_password = beyond_creds.password.body;
          }
          else
          {
            sudo_password = password;
          }
        }
      }
    }
    #
    # Gather lieberman creds
    #
    if ("Lieberman" >< auth_type || script_get_preference(ssh_prefix+"SSH Lieberman Host"+ssh_postfix))
    {
      lieberman_creds = lieberman_get_password(
        login   : account,
        type    : "OS_UnixAndCompat",
        prefix  : ssh_prefix + "SSH ",
        postfix : ssh_postfix
      );
      password = lieberman_creds.body.Password;
    }
    #
    # Gather cyberark creds
    #
    if ("CyberArk" >< auth_type || script_get_preference(ssh_prefix+"SSH CyberArk Host"+ssh_postfix))
    {
      if (script_get_preference(ssh_prefix+"SSH CyberArk Host"+ssh_postfix))
      {
        cyberark_result = cyberark_get_credential(username:account, prefix:ssh_prefix, postfix:ssh_postfix);

        if (cyberark_result.success)
        {
          password = cyberark_result.password;
          sudo = cyberark_result.sudo;
          sudo_password = cyberark_result.sudo_password;
          su_login = cyberark_result.su_login;
          sudo_path = cyberark_result.sudo_path;
          root = cyberark_result.root;
          private_key = cyberark_result.private_key;
        }
      }
      else if ("Auto-Discovery" >< auth_type)
      {
        pam = cyberark_auto_collect::pam;
        kb_path = "/auto_ssh/";

        # set parameter vars for AIM Webservice query to fetch password
        object = get_kb_item(pam + kb_path + "object");
        safe = get_kb_item(pam + kb_path + "safe");
        address = get_kb_item(pam + kb_path + "address");
        account = get_kb_item(pam + kb_path + "username");

        if (empty_or_null(object) || empty_or_null(safe) || empty_or_null(address))
        {
          dbg::detailed_log(
            lvl:1,
            src:FUNCTION_NAME,
            msg:"Host did not contain 1 or more CyberArk query parameter values. Will not attempt to retrieve password."
          );
        }
        else
        {
          ca_result = cyberark_auto_collect::get_AIM_secret(
            settings : "SSH settings",
            prefix   : ssh_prefix + "SSH ",
            postfix  : ssh_postfix,
            safe     : safe,
            username : account,
            address  : address,
            object   : object
          );

          if (!ca_result.success)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"Failed to retrieve password for CyberArk SSH Host.");
          }
          else
          {
            password = ca_result.password;
            sudo = ca_result.sudo;
            sudo_password = ca_result.sudo_password;
            private_key = ca_result.private_key;
          }
        }
      }
      else
      {
        ssh_prefix += "SSH PAM ";
        cyberark_result = cyberark::cyberark_rest_get_credential(
          username : account,
          prefix   : ssh_prefix,
          postfix  : ssh_postfix
        );

        if (cyberark_result.success)
        {
          password = cyberark_result.password;
          account = cyberark_result.username;
          sudo_password = cyberark_result.sudo_password;
          private_key = cyberark_result.ssh_key;
        }
      }
    }
    #
    # Gather Thycotic Creds
    #
    if ("Thycotic" >< auth_type)
    {
      thycotic_result = thycotic_get_credential(username:account,prefix:ssh_prefix,postfix:ssh_postfix);

      if (thycotic_result.success)
      {
        password = thycotic_result.password;
        sudo = thycotic_result.sudo;
        sudo_password = thycotic_result.sudo_password;
        su_login = thycotic_result.su_login;
        sudo_path = thycotic_result.sudo_path;
        root = thycotic_result.root;
        private_key = thycotic_result.private_key;
        passphrase = thycotic_result.passphrase;
      }
    }
    #
    # Centrify
    #
    if ("Centrify" >< auth_type)
    {
      centrify_result = centrify_get_credential(username:account,prefix:ssh_prefix+"SSH ",postfix:ssh_postfix);

      if (centrify_result.success)
      {
        password = centrify_result.password;
        account = centrify_result.username;
      }
    }
    #
    # Hashicorp
    #
    if ("Hashicorp" >< auth_type)
    {
      hashicorp_result = hashicorp::get_credential(username:account, prefix:ssh_prefix+"SSH ", postfix:ssh_postfix);

      if (hashicorp_result.success)
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg: "Successfully got Hashicorp PAM credentials.");

        password = hashicorp_result.password;
        private_key = hashicorp_result.private_key;
        passphrase = hashicorp_result.passphrase;
        account = hashicorp_result.username;
        sudo_password = hashicorp_result.sudo_password;
      }
    }
    #
    # Arcon
    #
    if ("Arcon" >< auth_type)
    {
      arcon_result = arcon::get_credential(
        username : account,
        prefix   : ssh_prefix + "SSH ",
        postfix  : ssh_postfix,
        type     : 'Linux'
      );

      if (arcon_result.success)
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg: "Successfully got Arcon PAM credentials.");

        password = arcon_result.password;
        account = arcon_result.username;
        sudo = arcon_result.sudo;
        sudo_password = arcon_result.sudo_password;
        sudo_path = arcon_result.sudo_path;
        su_login = arcon_result.su_login;
        root = arcon_result.root;
      }
    }
    #
    # Wallix
    #
    if ("Wallix" >< auth_type)
    {
      wallix_result = wallix::rest_get_credential(prefix:ssh_prefix+"SSH ", postfix:ssh_postfix);

      if (wallix_result.success)
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg: "Successfully retrieved Wallix PAM SSH credentials.");

        password = wallix_result.password;
        account = wallix_result.username;
        sudo_password = wallix_result.sudo_password;
        private_key = wallix_result.private_key;
        passphrase = wallix_result.passphrase;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg: "Failed to retrieve Wallix PAM SSH credentials.");
      }
    }
    #
    # Delinea
    #
    if("Delinea" >< auth_type)
    {
      delinea_result = delinea::rest_get_creds(prefix:ssh_prefix+"SSH ", postfix:ssh_postfix);
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:"The response from Delinea is: " + delinea_result.success);

      if(delinea_result.success)
      {
        dbg::detailed_log(
          lvl:2,
          src:FUNCTION_NAME,
          msg:"Successfully retrieved Delinea Secret Server PAM SSH credentials."
        );

        account = delinea_result.secrets.username;
        password = delinea_result.secrets.password;
        sudo_password = delinea_result.secrets.sudo_password;
        private_key = delinea_result.secrets.key;
        passphrase = delinea_result.secrets.passphrase;
      }
      else
      {
        dbg::detailed_log(
          lvl:1,
          src:FUNCTION_NAME,
          msg:"Failed to retrieve Delinea Secret Server PAM SSH credentials."
        );
      }
    }
    #
    # Senhasegura
    #
    if ("Senhasegura" >< auth_type)
    {
      senha_result = senhasegura::get_credential(prefix:ssh_prefix+"SSH PAM ", postfix:ssh_postfix);

      if(senha_result.success)
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"Successfully retrieved Senhasegura PAM SSH credentials.");

        account = senha_result.creds.username;
        password = senha_result.creds.password;
        sudo_password = senha_result.creds.sudo_password;
        private_key = senha_result.creds.private_key;
        passphrase = senha_result.creds.passphrase;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"Failed to retrieve Senhasegura PAM SSH credentials.");
      }
    }
    if ("QiAnXin" >< auth_type)
    {
      qax_result = qianxin::get_credential(prefix:ssh_prefix+"SSH PAM ", postfix:ssh_postfix, default_platform:"LINUX");

      if(qax_result.success)
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"Successfully retrieved QiAnXin PAM SSH credentials.");

        account = qax_result.creds.username;
        password = qax_result.creds.password;
        sudo_password = qax_result.creds.sudo_password;
        private_key = qax_result.creds.private_key;
        passphrase = qax_result.creds.passphrase;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"Failed to retrieve QiAnXin PAM SSH credentials.");
      }
    }
    if ("Fudo" >< auth_type)
    {
      fudo_result = fudo::get_credential(prefix:ssh_prefix+"SSH PAM ", postfix:ssh_postfix);

      if (dbg::is_error(fudo_result))
      {
        dbg::log_error(msg:"Failed to retrieve Fudo PAM SSH credentials.");
      }
      else
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"Successfully retrieved Fudo PAM SSH credentials.");

        # Note that username (account) does not get retrieved from the integration.
        password = fudo_result.password;
        sudo_password = fudo_result.sudo_password;
        private_key = fudo_result.private_key;
      }
    }
    ##
    # USE THIS SPACE TO EXPAND NEW PASSWORD MANAGERS
    ##

    # if no credentials are set continue to the next instance. Changing from isnull() to empty_or_null().
    # when PAM's do not return a cred, the password from script_get_preference() ln 317 retains it's "value"
    # of empty and not NULL. As a result, isnull(password) returns 0.
    if (empty_or_null(password) && empty_or_null(private_key))
    {
      #no credentials set for user account
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'No credentials set for account (' + account + ')');
      continue;
    }

    dbg::detailed_log(
      lvl:1,
      src:FUNCTION_NAME,
      msg:'SSH Settings',
      msg_details: {
        'Credential type': {lvl:1, value:auth_type},
        'Username': {lvl:1, value:account},
        'Elevate user': {lvl:1, value:root},
        'Elevate with': {lvl:1, value:sudo}
      }
    );

    if (sudo =~ "^none$")
    {
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"Fixed SC's 'none' elevation method to 'Nothing'.");
      sudo = 'Nothing';
    }

    # storage for credentials information
    result_array = {};
    if (j == 0)
    {
      # these values are single instance storage value or legacy values and only need set one time.

      # less than nessus 6 only
      if (!isnull(cert))
        result_array["Secret/SSH/publickey"] = cert;
      if (!isnull(kdc))
        result_array["Secret/kdc_hostname"] = kdc;
      if (!isnull(kdc_port))
        result_array["Secret/kdc_port"] = int(kdc_port);
      if (!kdc_transport || ";" >< kdc_transport || kdc_transport == "tcp")
        result_array["Secret/kdc_use_tcp"] = TRUE;

      # global
      if (!isnull(client_ver))
        result_array["SSH/clientver"] = client_ver;
      if (!isnull(pref_port) && int(pref_port))
        result_array["Secret/SSH/PreferredPort"] = int(pref_port); # global
      if (least_priv == "yes")
        result_array["SSH/attempt_least_privilege"] = TRUE;
    }

    if (!isnull(account))
      result_array["Secret/SSH"+jindex+"login"] = string(account);
    if (!isnull(root))
      result_array["Secret/SSH"+jindex+"root"] = string(root);
    if (!isnull(cert))
      result_array["Secret/SSH"+jindex+"certificate"] = string(cert);
    if (!isnull(private_key))
      result_array["Secret/SSH"+jindex+"privatekey"] = hexstr(private_key);
    if (!isnull(passphrase))
      result_array["Secret/SSH"+jindex+"passphrase"] = string(passphrase);
    if (!isnull(password))
      result_array["Secret/SSH"+jindex+"password"] = string(password);
    if (!isnull(custom_prompt))
      result_array["SSH"+jindex+"custom_password_prompt"] = string(custom_prompt);
    if (!empty_or_null(target_priority_list))
      result_array["SSH"+jindex+"target_priority_list"] = string(target_priority_list);
    if (!isnull(auth_type))
      result_array["SSH"+jindex+"cred_type"] = string(auth_type);

    # save Kerberos preferences
    if (kdc && kdc_port && realm)
    {
      result_array["Secret/SSH"+jindex+"kdc_hostname"] = string(kdc);
      result_array["Secret/SSH"+jindex+"kdc_port"] = int(kdc_port);
      result_array["Kerberos/SSH"+jindex+"realm"] = string(realm);

      if (!kdc_transport || ";" >< kdc_transport || kdc_transport == "tcp")
        result_array["Kerberos/SSH"+jindex+"kdc_use_tcp"] = TRUE;
    }

    EsclPwdType = "sudo";
    if (sudo == "sudo")
      result_array["Secret/SSH"+jindex+"sudo"] = SU_SUDO;
    else if (sudo == "su")
      result_array["Secret/SSH"+jindex+"sudo"] = SU_SU;
    else if (sudo == "su+sudo")
      result_array["Secret/SSH"+jindex+"sudo"] = SU_SU_AND_SUDO;
    else if (sudo == "dzdo")
      result_array["Secret/SSH"+jindex+"sudo"] = SU_DZDO;
    else if (sudo == "pbrun")
      result_array["Secret/SSH"+jindex+"sudo"] = SU_PBRUN;
    else if (sudo == "Cisco 'enable'")
      EsclPwdType = "Cisco enable";
    else if (sudo == "Checkpoint Gaia 'expert'")
      EsclPwdType = "Checkpoint expert";

    if (sudo)
      result_array["Secret/SSH"+jindex+"sudo_method"] = sudo;
    if (su_login =~ '^[A-Za-z0-9._-]+$')
      result_array["Secret/SSH"+jindex+"su-login"] = string(su_login);

    sudo_password = string(sudo_password);
    if(strlen(sudo_password) > 0)
    {
      if (EsclPwdType == "sudo")
        result_array["Secret/SSH"+jindex+"sudo-password"] = sudo_password;
      else if (EsclPwdType == "Cisco enable")
        result_array["Secret/SSH"+jindex+"enable-password"] = sudo_password;
      else if (EsclPwdType == "Checkpoint expert")
        result_array["Secret/SSH"+jindex+"expert-password"] = sudo_password;
    }
    if (sudo && sudo_path && preg(pattern:"^[A-Za-z0-9./-]+$", string:sudo_path))
    {
      if (!preg(pattern:"/$", string:sudo_path))
        sudo_path += '/';

      result_array["Secret/SSH"+jindex+"sudo_path"] = string(sudo_path);
    }

    result_list[j] = result_array;
    j++; # increase the index counter for the kb entry
  }

  return result_list;
}

##
# Takes the input from ssh_settings_get_settings()
# to input into the kb.
#
# @param [ssh_settings:list] list of array values to get inserted in the kb
#
###
function insert_ssh_settings_kb(ssh_settings)
{
  var sshi, sshk;

  for (sshi of ssh_settings)
  {
    for (sshk in sshi)
    {
      set_kb_item(name:sshk, value:sshi[sshk]);
    }
  }
}

##
# set ssh_settings known host information
##
function ssh_settings_known_host()
{
  var file,known_hosts,lines,line,data,pref_port,port,revoked,
    ca,tmp,hostname,type,key,cert,h_s,hn,ip,e,n;

  known_hosts = script_get_preference_file_content("SSH known_hosts file : ");
  # If running from command line, prompt for known_hosts file
  if (COMMAND_LINE)
  {
    file = script_get_preference("SSH known_hosts file : ");
    display('\n');
    if(!empty_or_null(file))
    {
      known_hosts = fread(file);
      if(!known_hosts)
      {
        display("Could not read the file ", file, "\n");
        exit(1);
      }
    }
  }

  if (!isnull(known_hosts))
  {
    lines = split(known_hosts, keep:FALSE);
    for (line of lines)
    {
      # The man page for sshd(8) says "Lines starting with `#' and empty lines are ignored as comments."
      if (line =~ "^\s*#" || line =~ "^\s*$")
        continue;

      data = split(line, sep:' ', keep:FALSE);
      if (pref_port && int(pref_port))
        port = pref_port;
      else
        port = 22;

      revoked = FALSE;
      ca = FALSE;
      if (data[0] == '@revoked' || data[0] == '@cert-authority')
      {
        if (data[0] == '@revoked')
          revoked = TRUE;
        if (data[0] == '@cert-authority')
          ca = TRUE;

        data = [data[1], data[2], data[3]];
      }

      # if the second field (index 1) is _not_ all numeric (i.e. is not the bits field)
      # this line refers to an SSH2 key or certificate
      if (data[1] !~ "^\d+$" && max_index(data) >= 3)
      {
        hostname = data[0];
        type = data[1];
        key = data[2];

        # if a certificate was provided instead of a key, retrieve the host's public key from the cert
        if ("-cert-" >< type)
        {
          cert = base64decode(str:key);
          cert = parse_ssh_cert(cert);
          key = get_public_key_from_cert(cert);

          # key will only be NULL if the public key type is unknown or unsupported
          if (isnull(key))
            continue;

          if ("ssh-rsa" >< type)
            type = "ssh-rsa";
          if ("ssh-dss" >< type)
            type = "ssh-dss";
          if ("ssh-ed25519" >< type)
            type = "ssh-ed25519";
          key = base64encode(str:key);
        }

        if (revoked && patterns_match_this_host(hostname, port))
        {
          set_kb_item(name:"SSH/RevokedKey", value:key);
        }
        else if (ca && patterns_match_this_host(hostname, port))
        {
          set_kb_item(name:"SSH/CAKey", value:key);
        }
        else if (hostname =~ "^\|1\|")  # HMAC_SHA1 hash of the hostname
        {
          hostname -= "|1|";
          h_s = split(hostname, sep:'|', keep:FALSE);
          h_s[1] = base64decode(str:h_s[1]);
          h_s[0] = base64decode(str:h_s[0]);

          if (h_s[1] == HMAC_SHA1(key:h_s[0], data:get_host_ip()) ||
              h_s[1] == HMAC_SHA1(key:h_s[0], data:'[' + get_host_ip() + ']:' + port) ||
              h_s[1] == HMAC_SHA1(key:h_s[0], data:'[' + get_host_name() + ']:' + port) ||
              h_s[1] == HMAC_SHA1(key:h_s[0], data:get_host_name() + ',' + get_host_ip()) ||
              h_s[1] == HMAC_SHA1(key:h_s[0], data:get_host_name()))
          {
            replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
          }
        }
        else if ( hostname =~ "^\[.*\]:[0-9]+" )
        {
          if (hostname == "[" + get_host_ip() + "]:"+ port  || hostname == "[" + get_host_name() + "]:"+ port)
            replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
        }
        else if ( "," >!< hostname )
        {
          if (hostname == get_host_ip() || hostname == get_host_name())
            replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
        }
        else
        {
          hn = preg_replace(pattern:"^([^,]*),.*", string:hostname, replace:"\1");
          ip = preg_replace(pattern:"^[^,]*,(.*)", string:hostname, replace:"\1");

          if (ip == get_host_ip() && hn == get_host_name())
            replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
        }
      }
      # if fields 2-4 (indices 1-3) _are_ all numeric (the bits, exponent, and modulus fields)
      # this line refers to an SSH1 key
      else if (data[1] =~ "^\d+$" && data[2] =~ "^\d+$" && data[3] =~ "\d+$")
      {
        hostname = data[0];
        e = data[2];
        n = data[3];

        if (hostname == get_host_ip() || hostname == get_host_name())
          replace_kb_item(name:"SSH/KnownFingerprint/ssh-rsa1", value:e + "|" + n);
      }
    }

    #This section initializes known fingerprints to the base64 encoding of @NOTSET@
    #The string "@NOTSET@" in base64 is QE5PVFNFVEA=
    if (!get_kb_item("SSH/KnownFingerprint/ssh-rsa1"))
      set_kb_item(name:"SSH/KnownFingerprint/ssh-rsa1", value:"QE5PVFNFVEA=");

    # this lets sshlib know that a host key was not provided for this host.
    # (It is not possible to use CAs with ssh-rsa1)
    if (!get_kb_list("SSH/CAKey"))
    {
      if (!get_kb_item("SSH/KnownFingerprint/ssh-rsa"))
        set_kb_item(name:"SSH/KnownFingerprint/ssh-rsa", value:"QE5PVFNFVEA=");

      if (!get_kb_item("SSH/KnownFingerprint/ssh-dss"))
        set_kb_item(name:"SSH/KnownFingerprint/ssh-dss", value:"QE5PVFNFVEA=");

      if (!get_kb_item("SSH/KnownFingerprint/ecdsa-sha2-nistp256"))
        set_kb_item(name:"SSH/KnownFingerprint/ecdsa-sha2-nistp256", value:"QE5PVFNFVEA=");

      if (!get_kb_item("SSH/KnownFingerprint/ecdsa-sha2-nistp384"))
        set_kb_item(name:"SSH/KnownFingerprint/ecdsa-sha2-nistp384", value:"QE5PVFNFVEA=");

      if (!get_kb_item("SSH/KnownFingerprint/ecdsa-sha2-nistp521"))
        set_kb_item(name:"SSH/KnownFingerprint/ecdsa-sha2-nistp521", value:"QE5PVFNFVEA=");

      if (!get_kb_item("SSH/KnownFingerprint/ssh-ed25519"))
        set_kb_item(name:"SSH/KnownFingerprint/ssh-ed25519", value:"QE5PVFNFVEA=");
    }
  }

}

var ssh_settings = ssh_settings_get_settings();
insert_ssh_settings_kb(ssh_settings:ssh_settings);
ssh_settings_known_host();
