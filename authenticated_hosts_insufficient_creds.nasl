#TRUSTED 0918b98a843d16588287aa487743ae51527a9a30a5e2cbf156fc2c7b7db11f33b87bbc1ba026ee20299a0ea9a4ad098afdd1a62e1b8bf61250fb9a1f8d667a905682979541a4f98126d038992850ed6d16099c99b3ee212565afccfe492d3250640adfef5d8cb3295cfef75ae6383dc673e8413f7a2141ee602714678eaf5ce8016cece03af67ab1db374df5744b3704c7c6145fe27a63c895f4b27ab3a566831918136ff7e5d328e6c85b79fdd1453fe86f1466f163921d32fc5f43429713f8b749da30ae17f26a066d3c5adca56128d090b33ede14d700973991a802d5055ae8df253a407aa15af7a3abf13e18dd7a6a30a866046f1b605294fc8761615ed67bda77ea4082f88208d65dceb6e8f6d479e720279f39cfb210fcae5505227559c253963a45536827a4786100e40bed042fe644fd408995e34f4893244ac447000481229cb4b14a6544a49b02612af8e3e18314108a1be8a8851bed2fe6388b93c4a68e83f8b6a6c75a385da7307ed21e7445ba5953d8e1acbf04a380f6e61214351d545e7fdc272c0b33e9f4d37ffb19d75f9e829ec11d89e7effc9dc75dc8ff7be92a387f9040e0ac1d89f0e737409ce6653779e7b13621840a0b23bc6c6a4e16d7874805798ac4293b0f668a50966c6516fd657a23f96e7165e665d90f3bd4d69088ed0809e834ade7de31e731671c0931589ed8f8809539fcd32e85cfe89e
#TRUST-RSA-SHA256 0d7086b53bca80062519135576980b2c337e04b8e416ebe52adbf66ea009a282217493d1d542024908596d6e2f9504fbce31be1b5c5a153745d95ae6796d522420fd49c474b204256a0353dfac9c9c9e27cb2bdae05c45d620fcb580b1f7049badddd91e6eb114fae2c4849f1720df3f2d2584fab704c4ae684ae4eb858edb106d2bdb36339bb4130d83173afad4bc3400f24f76e93b5ed0d677bacd8e334a9b59509892f33b3b701512bca23c8f8a103474187d9e944113578a1643d35ce1b2841faac79c0c7fdb4f70309fc16be1343dc33861ef3cff23ac62b9697fa1f2ba3eb6d9c40812bb5375ffd318f43c856cab59805f052d90ab6ed21ff6493f2fc294112d5963f9ac9aa38ddfbca9938e66dc03595494a0db29adeb0029a271bd2c37b487ac65f4a3f15d3ff79840346ae3895ced8224f7c88509d9804b684547db62db1c0c9de3fc636e78fedef2f871d50a18d303ea022906cf1c5f8224c53b55ba55c1ba1d81bc611fd1fc89da8fb508fd566508b91a813ad5cfa247a1c2ba3f519c42ad09a5dabcbdb63f365692a565c9f615de2f908cd329fc25583c0ea09bf047e4048e83538dc05757acd2082bbd473147e1a892e090464f0059311ca0ffd440ae5a4f6d3f18837a74fb0ec7294f8ce2f27155cd95d88e9b30da98456f9b2fec138fc7d7f3d1ae7842f5bf3388132bc8a9b2e0ce38af966e49f4e4956750
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110385);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/25");

  script_xref(name:"IAVB", value:"0001-B-0502");

  script_name(english:"Target Credential Issues by Authentication Protocol - Insufficient Privilege");
  script_summary(english: "Reports insufficient privilege issues encountered on a protocol with valid credentials.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to log in to the remote host using the provided
credentials. The provided credentials were not sufficient to complete
all requested checks.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to execute credentialed checks because it was
possible to log in to the remote host using provided credentials,
however the credentials were not sufficiently privileged to complete
all requested checks.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("spad_log_func.inc");
include("cred_func.inc");
include("lcx.inc");

global_var auth_ok_count = 0;

var atts_path;
if (platform() == 'WINDOWS')
  atts_path = nessus_get_dir(N_STATE_DIR) + "\plugins-attributes.db";
else
  atts_path = nessus_get_dir(N_STATE_DIR) + '/plugins-attributes.db';

function report_problems(prefix, proto, db, port, user)
{
  var max_privs = NULL;
  if (lcx::check_localhost() && (proto == "SMB" || proto == "SSH"))
    return 0;

  local_var kb_prefix = prefix + proto + "/" + port;
  local_var report = '';
  local_var problem_list, problem;
  local_var pattern, matches, plugin, id, atts_path, rows, pdict, plugin_id, rl;


  if (!get_kb_list(kb_prefix + "/Success")) return 0;
  auth_ok_count++;
  max_privs = get_kb_item(kb_prefix + "/MaxPrivs");
  if (isnull(max_privs) || max_privs == 1) return 0;
  if (proto == 'SSH' && !lcx::has_ssh_priv_failures()) return 0;
  if (proto != 'SSH' && !get_kb_list(kb_prefix + "*/Problem")) return 0;

  report = get_credential_description(proto:proto, port:port, user:user);

  if (!empty_or_null(report))
    report = '\nNessus was able to log into the remote host, however this credential' +
             '\ndid not have sufficient privileges for all planned checks :\n\n' + report;

  if(proto == 'SMB')
  {
    problem_list = get_kb_list(kb_prefix + "*/Problem");
    pdict = {};
    if(!isnull(problem_list))
    {
      foreach problem(keys(problem_list))
      {
        pattern = "^" + kb_prefix + "/([\w.-_{}]+)/Problem";
        matches = pregmatch(pattern:pattern, string:problem, icase:FALSE);
        plugin_id = "<error unknown>";

        if (!isnull(matches) && !isnull(matches[1]) && db > 0)
        {
          rows = db_query(db:db, query:'SELECT * FROM Plugins WHERE plugin_fname = ?', matches[1]);
          if (!isnull(rows[0]))
            plugin_id = rows[0]['id'];
        }

        #prevent duplicate reports
        if(!isnull(pdict[plugin_id + problem]))
          continue;

        rl = "Plugin " + plugin_id;
        problem = data_protection::sanitize_user_paths(report_text:problem_list[problem]);
        rl += ":  Permission was denied while " + problem + '.\n';

        pdict[plugin_id + problem] = rl;
      }

      if(len(pdict) > 0)
      {
        report += '\n\nProblems:\n';
        foreach problem(sort(keys(pdict)))
          report += pdict[problem];

        report += '\n';
      }
    }

  }
  else if (proto == 'SSH')
  {
    report += '\n\nSee the output of the following plugin for details :\n' +
      '\n  Plugin ID   : 102094' +
      '\n  Plugin Name : SSH Commands Require Privilege Escalation\n';
  }

  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

  return 1;
}

var successes = get_kb_list("Host/Auth/*/Success");

var num_reported = 0;
var db = 0;

var pat = "^Host/Auth/([A-Za-z]+/[0-9]+)/.*";

var win, match, protoport, tmp;
foreach win (keys(successes))
{
  match = pregmatch(pattern:pat, string:win, icase:FALSE);
  if (isnull(match)) continue;

  protoport = match[1];
  tmp = split(protoport, sep:'/', keep:FALSE);

  #If the first attempt to open the attributes DB fails db will equal -1. We will not try again.
  if(db == 0 && tmp[0] == 'SMB')
    db = db_open2(path:atts_path, use_default_key:TRUE, readonly:TRUE);

  num_reported += report_problems(prefix:"Host/Auth/", proto:tmp[0], port:tmp[1], db: db, user:successes[win]);
}

if(db > 0)
  db_close(db);

if (num_reported == 0)
{
  if (auth_ok_count > 0)
    exit(0, "Authentication successes; did not report insufficient credential issues.");
  else if (lcx::svc_available())
    exit(0, "No authentication successes using user supplied credentials to report.");
  else exit(0, "No local checks ports or services were detected.");
}

