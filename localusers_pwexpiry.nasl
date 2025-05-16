#TRUSTED 50dfc39992d7ffacfb4bdfb5bb60f419f7733b9bf09f3d763da2f6c1bb10e26f4c71e24cc6ecf28c4aa87305fa969bd816b18acc7e91b71b05bfed1deb42242b3b4552dec7ff227962e1704f6f85e202a608e79495d8b72c2972656b0fea84603ebed0216ff17b9b5836d5cc1b5da5ef792ee14824e9a918c57ae93598d13a93e8785e4458c0c8192370838c86a8ea64c34372f00485348fc5e963bed96c8da0ceee98ee4a166bbbd99c86674e1dda70348628229bdff1b4db26855633997ea3bf45e224534a561a534a03c0160f483bcd05863c577eb0640c427bf781d4f63ddb3b6db2cc4aaa0c56d103eea901c9bd927081cbfced34fdc377fa172d4248c3b519a3169e43b6dcc6b16557b2fe0510256f6115bab3f9f9325aa0e8f83f65a4e93df02a5eaec33d12a8bf1d545a9d5b7ca57165ac2b041697795ea5d850999ff0098c5b10dce8d98f2447a7eee8ecb9b29a2b6c6a524b3ddb8e3176bb13de056f4ff8f53c6a180d2e3e3602a5164a94b7c0997b7a19b81022808cfb7afe24a18463312ee9fbfb1a6c8e306b87faf0d00a00396c30a8e4f194bee42e0de3969afcbe5f382a7fa6b6ca4994b6cab277978013adc5c51b16e74cc11d905f6b50296b8ac6d20cd0177402be675c9b377bbf75a4bd00ba874abc695dd1ab6e54f16955c89fceea61007c154854b0653f282e30650c328ec0c9f721962282e022926d
#TRUST-RSA-SHA256 7483d103b015c915f39bc0cd7452fed1b8f2a45c2e40d37bd27b761b4f45bdd550651fb3029f965df72a0b7a717835a96e1a6d6467d790f49e816ba75663be7cc0ba80bcaf18430f7ff7c0c8f47c490b27be917d02960bce6345dd070ebcfec3c8cc20f4202bd2d5ef1e5d4ebb0fa6d23c3428fad755e6b2acbb806c91cb5248f94a6dae5c624d13e743d3029c6a5794b9cc8fdd4064bc1bbcb683957e88b19e3baccc8964fea07eddb7890bdc9e0dfa66c57cb07a1404c66d8162a4c423b18c1d13b4495622b19b8c10e5cae913f95edad784e6f24b2fc5232da6a1977fb5f0afd0203938ebf64fc094094d9d031b12a4b6b62d3dfd54504f3624f80b4aabf80cf0cab317a6342a749280e314065625affe224a86fdbe9ab935151cccd04b98d13633b2448f740fc2629ecd4d8a77af421e7430328429940c978c5978052e3688df604bf97df5c7b89a7083acbd1155de06b9b7f8908e3cc0182decdec9a84cdcb57aebc931568a99b26f6b0b0f3d126af9916f11318cab6050fbbfedb7a98e8db615a264f08f5ddd62b26501a9600eea491aa4a21cd6daaa0243245e24061a9240cdb3ee297da5294a937c3a0fdbdf7fd0eec70268a847a1fae375d1b9394347bf53cbddce11a637c9b471fd9c505363aba84c81f54102068e5d1db1844eed985fcffd6d3554b84918e20c43305bfd69d7f371243b0fb4f58262b2bb242075
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83303);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");


  script_name(english:"Unix / Linux - Local Users Information : Passwords Never Expire");
  script_summary(english:"Lists local users whose passwords never expire.");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"synopsis", value:
"At least one local user has a password that never expires.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to list local users
that are enabled and whose passwords never expire.");
  script_set_attribute(attribute:"solution", value:
"Allow or require users to change their passwords regularly.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("global_settings.inc");
include("misc_func.inc");
include("data_protection.inc");

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Do not run against Windows and some Unix-like systems
supported = FALSE;
dist = "";
if (
  get_kb_item("Host/CentOS/release") ||
  get_kb_item("Host/Debian/release") ||
  get_kb_item("Host/Gentoo/release") ||
  get_kb_item("Host/Mandrake/release") ||
  get_kb_item("Host/RedHat/release") ||
  get_kb_item("Host/Slackware/release") ||
  get_kb_item("Host/SuSE/release") ||
  get_kb_item("Host/Ubuntu/release")
)
{
  supported = TRUE;
  dist = "linux";
  field = 5;
}
else if (
  get_kb_item("Host/FreeBSD/release") 
)
{
  supported = TRUE;
  dist = "bsd";
  field = 6;
}

if (!supported) exit(0, "Account expiration checks are not supported on the remote OS at this time.");

# We may support other protocols here
if ( islocalhost() )
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

if (dist == "linux")
  cmd = "cat /etc/shadow";
else
  cmd = "cat /etc/master.passwd";

validfile = FALSE;
noexpiry = make_list();
buf = info_send_cmd(cmd:cmd);
if (info_t == INFO_SSH) ssh_close_connection();
if (buf)
{
  lines = split(buf);
  if (!empty_or_null(lines))
  {
    foreach line (lines)
    {
      acct_fields = split(line, sep:':', keep:FALSE);
      if (max_index(acct_fields) >= 7)
      {
        validfile = TRUE;
        # Skip locked / expired accounts
        if (acct_fields[1] == '*' || acct_fields[1] == '!' || acct_fields[1] == "!!" || acct_fields[1] == "!*")
          continue;
        if (dist == "bsd" && acct_fields[1] =~ '\\*LOCKED\\*')
          continue;

        if (dist == "linux" && !empty_or_null(acct_fields[7]))
        {
          if (!empty_or_null(acct_fields[6]))
            timetoexpire = int(acct_fields[6]) * 86400;
          else timetoexpire = 0;

          expire_timestamp = int(acct_fields[7]) * 86400 + timetoexpire;
          current_timestamp = unixtime();
          if (expire_timestamp < current_timestamp)
            continue;
        }

        if (empty_or_null(acct_fields[field - 1]) || int(acct_fields[field - 1]) == 99999 || (dist == "bsd" && acct_fields[field - 1] == 0))
          noexpiry = make_list(noexpiry, acct_fields[0]);
      }
    }
  }
}
else
{
  errmsg = ssh_cmd_error();
  if ('Permission denied' >< errmsg)
    exit(1, "The supplied user account does not have sufficient privileges to read the password file.");
  else
    exit(1, errmsg);
}
if (!validfile)
  exit(1, "The password file did not use the expected format.");

if (!empty_or_null(noexpiry))
{
  count = 0;
  foreach user (noexpiry)
  {
    count += 1;
    set_kb_item(name:"SSH/LocalUsers/PwNeverExpires/"+count, value:user);
  }

  if (report_verbosity > 0)
  {
    users = join(noexpiry, sep:'\n  - ');
    users = data_protection::sanitize_user_enum(users:users);
    report =
      '\nNessus found the following unlocked users with passwords that do not expire :' +
      '\n  - ' + users + '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
