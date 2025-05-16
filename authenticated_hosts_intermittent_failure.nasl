#TRUSTED 80c3677d8c54af4c460933fcf10141964744223ce26fda8a9b419bcb0306f69d437d9cf54624d1e6466456a46524c66734b1036a2688e813d11bec5700a541afdc425e4a7081e14b3a4252fd5d8a9311c59162e1a30c42e05ac53d7c10cd9db34090e27d53e62fb56b5545c16923497c700e50140153a487aa6ea2adeac2f6b28beab1fd371115d3f3d6c4d7826e1fbf2a0aaa02cda16d389fb51b656aaf2c12bb98047409d9989075d46dd02325f822c3c62661aa8b5e6d6cd1c3209eb66c340b4a300a709245c6d0d26e98bc30fc9e0968731b92329d572244bfc034c7eaa8970443532cfc5dd96882625fed1bede727bb1dc45eebbb8c85927627fcbc3f7a298745445f46872797c63a6131a52f8b4cd15888970a4ccc16e4176ce3a77f964e0b234f757779e2cadba34fbb61aa5a68b9e390b0eaf01d4b0d421a3328217991d99b37896110e96e38cb6a33e1439aa0dc22cf0fb20291bb994ed2ff71cf6ab9a9666c4d3daca29db6b29dbd00213c98c794c17bc6d93275bfe076abc8ea4a5e236b9a065bbc2e53a03a3723a268707c8d315f5dd0af09549cd7062d28f09955b63dd4006fc3ec57645647cf928847c45f7c364816b987f7f37b7f4434eacf02c09403b2da97af4cec11cb41790e9c39bfa72eea5694136ddb18a1e4711730e1c760fb2f8140612a151979f5962643af97ad5c60d7209baab8db0168ee396e
#TRUST-RSA-SHA256 a93e96a1109e7bcf1b6183cb4bcb3d5d8c6c92d9d4318871aec86d632762090e59659a2770f8234c795d0e0d61c0f001b1f4e7b57b8b87661a891d8287a0e360261eb8804a7703d1613831387b6c72a64a50a96a4e5b6574ed5aeb92c9e29289972bff57e7a5021e41a3a3564f89460f8c7f1788d665e997f8f9183ad8d6b93bc79b710dd03d933950a81455b96849b44195807c0cf716207eaa8546b04a63e99ed28c608eb95dddb60f8569baaa64bab058f57c92d984b3e98fbf5481217d98a4de88199ed77fbd3e517046629100c36d4356afff5ff6a3a724465c1cdbc83068d4fee2086cdc4a446d6beeaa42550a5cc07738a553b93586fccf1b4936e32ea0b1fe46c589d946f42e78e79992eda3bd2126cb215d4b17cfeb1e2b9089031d47bc071692b7b26214c3bd525f89c641ea04705ea64b92e4fa262b9c03ec1de013566f1ccb022cba0b66f9194a69af127b36ec782192da3d493f6769149718555c7ce39f604d133af2f07851e60bb927ce4c8c2ba88bc977ca084b942c1e9563764e518148bae0731ff9b0777d94dfb3a60b6a4f4d35a2ff5f0481f17337d06e4471f117bde8fed15ea1e964ac47a9bb8d86338b2bdd3f85ef5df3f80fcfe8b6e9a963c97ea576f7b952dfb9d57fa033a4ea5bf455f2c43247725250f4c02032af3dd0370b3faa3dc44f6fc214113e9efa9aa7fb139a4f0faf3e5bc88acce8a7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117885);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/25");

  script_xref(name:"IAVB", value:"0001-B-0509");

  script_name(english:"Target Credential Issues by Authentication Protocol - Intermittent Authentication Failure");
  script_summary(english:"Reports intermittent authentication failures on a protocol with valid credentials.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to log in to the remote host using the provided
credentials, but there were intermittent authentication failures.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to successfully authenticate to the remote host on an
authentication protocol at least once using credentials provided in
the scan policy.

However, one or more plugins failed to authenticate to the remote host
on the same port and protocol using the same credential set that was
previously successful. This may indicate an intermittent
authentication problem with the remote host, which could be caused by
session rate limits, session concurrency limits, or other issues
preventing consistent authentication success.

These intermittent authentication failures may have affected the
results of some plugins. See plugin output for failure details.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/02");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("cred_func.inc");
include("lcx.inc");

global_var auth_ok_count = 0;

function report_problems(prefix, proto, port, user)
{
  if (lcx::check_localhost() && (proto == "SMB" || proto == "SSH"))
    return 0;

  local_var kb_prefix = prefix + proto + "/" + port;
  local_var report, info, lines, stats;

  if (!get_kb_item(kb_prefix + "/Success")) return 0;
  auth_ok_count++;
  if (!get_kb_item(kb_prefix + "/Failure")) return 0;
  var proto_g = lcx::PROTO_GLOBALS[proto];
  var errs = lcx::get_issues(type:lcx::ISSUES_AUTH, port:port,
    proto:proto_g, user:user);
  if (!errs || max_index(errs) < 1) return 0;

  report = get_credential_description(port:port, proto:proto, user:user);

  if (!empty_or_null(report))
    report = '\nNessus was able to successfully log into the remote host as :\n\n' + report;

  var record = lcx::get_issues(type:lcx::AUTH_SUCCESS, port:port,
      proto:proto_g, user:user);
  if (record && max_index(record) > 0)
  {
    record = record[0];
    report += '\n' +
      '\nSuccessful authentication was reported by the following plugin :\n' +
      '\n  Plugin      : ' + record['plugin'];
    if (record['plugin_id']) report +=
      '\n  Plugin ID   : ' + record['plugin_id'];
    if (record['plugin_name']) report +=
      '\n  Plugin Name : ' + record['plugin_name'];
  }

  report += '\n' +
    '\nHowever, one or more subsequent plugins failed to authenticate to the' +
    '\nremote host on the same port and protocol using the same credential' +
    '\nset that previously succeeded. This may indicate an intermittent' +
    '\nauthentication problem with the remote host which may have affected' +
    '\nthe results of the following plugins.\n';

  if(get_kb_item("Host/OS/ratelimited_sonicwall"))
    report += '\nNote: Host has been identified as a SonicWall device that may be SSH rate limited.\n';
  if(get_kb_item("Host/OS/ratelimited_junos"))
    report += '\nNote: Host has been identified as Juniper Junos device that may be SSH rate limited.\n';
  if(get_kb_item("Host/OS/ratelimited_omniswitch"))
    report += '\nNote: Host has been identified as a Alcatel-Lucent OmniSwitch device that may be SSH rate limited.\n';

  # Add some stats to the top in case there are a lot of duplicates
  stats = lcx::get_issue_message_counts_text(issues:errs);
  if (stats) report += '\nError message statistics :\n\n' + stats;

  # Add details
  foreach var err (errs)
  {
    info += '\n' +
      '\n  - Plugin      : ' + err['plugin'];
    if (err['plugin_id']) info +=
      '\n    Plugin ID   : ' + err['plugin_id'];
    if (err['plugin_name']) info +=
      '\n    Plugin Name : ' + err['plugin_name'];
    info +=
      '\n    Message     : ';
    # If message is more than one line or would exceed 70 chars with
    # the label field, add a newline
    lines = split(err['text']);
    if (max_index(lines) > 1 || strlen(lines[0]) > (70 - 18))
      info += '\n';
    info += err['text'] + '\n';
  }

  if (info) report += '\nFailure Details :' + info;
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

  return 1;
}

var successes = get_kb_list("Host/Auth/*/Success");

var num_reported = 0;

var pat = "^Host/Auth/([A-Za-z]+/[0-9]+)/.*";

var win, match, protoport, tmp;
foreach win (keys(successes))
{
  match = pregmatch(pattern:pat, string:win, icase:FALSE);
  if (isnull(match)) continue;

  protoport = match[1];
  tmp = split(protoport, sep:'/', keep:FALSE);
  num_reported += report_problems(prefix:"Host/Auth/", proto:tmp[0],
    port:tmp[1], user:successes[win]);
}

if (num_reported == 0)
{
  if (auth_ok_count > 0)
    exit(0, "Authentication successes did not encounter subsequent failures.");
  else if (lcx::svc_available())
    exit(0, "No authentication successes using user supplied credentials to report.");
  else exit(0, "No local checks ports or services were detected.");
}
