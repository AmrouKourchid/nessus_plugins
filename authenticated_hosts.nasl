#TRUSTED 8b095a03ed5fed6eb7c7319d8fc07575b633c9ed938cc97eb905be1499fc13534d5c65811ccbb70380b11ffc8fd930308c293b25681056c5ac12b699326f75dc8e337238d52cedc28dee2ec69eb6a973d778148c1cd1b5ee374bcbe6c8a90553faa1f6e90eec690497cdb0bf0f2581aad93bb67f6245465ee7704e7424429401df3b34dc60fe299e5d8749416368810bcd3d6db802f2ef78b1ed8b6a4115cc1547a27476e736fe687efe95580cc8794487d5884ceaed35f9f2ff675518cd03396733ee2fc33907c5ff566af15ceb81c2d51be106e3c78c89a0916452b4ae3f0a9beeb20dd1ef3d1f921132a7939297f05691388ec78ab7e7f0541bb06fbfda3e4c3ec1187f2652dac388ad13a024c7a1f7167bd50018015e1b4ca81325be7bf79ee52c4447b6105ff50d2aad93a6a055b879cf0b4b8f2570b9eaa5eec7a4209bd50e15d119887ad433a4fe62b91067a9fa9d3aab8639900a6dc5357dcd5e61d9229491d74eea13b47bcf11b31f45ced26bc2cf71a3b2485beb836f3f90e0d89f7b5ca456185baca74eb837c3bd8a51657184df1575600f3a388b36c6b871ba721c9fd73587f3e81ba192df2b2cfb6586f663ada60767abccdb1b4fc7afbd43687517b4ee160755a4f8fb225de8a4dfdda4491e709a8bb3ca1121191c4faa9b679211bc3b6af795b44566861d86ffdb690d9433a1a4720ba9ac61fe4c7f16bce5
#TRUST-RSA-SHA256 448b848ad8d6491507c333e90906454cad51621670c15e0a8bdece3f070c1cc4ed91b4e8c00c06f383080a7ad8211a89d40e0f8c5fbe755d68a93caf7c881551d615108850863c597e9350a5503229ab27e41ae554dd37f92cffbc05916ab4294cbe0c8b41afa2774820f801204a393b5e01ab092edb2749a9922ff5934a04118849c911021bc953d2cfcd042266b15fed4b05a371a24c38e53782707f203e2004db9b93b188b1f74ada329d49b44862330c71385f9dedcd5e4ecaebb4a60d29476ef72e9bbc5a849781b56ea3731e0f66527f5606cc5c5fad5f6d29ab707c343ff7dd1a46542c6263d263fc604ab187ca2bfcac6ad23de24b310b3d40f78999348fa28f39c2c7c5e7bc1313cfa1c9196a5c366547500a2ee6afaf6eec3599b56120d7cbb5c0a68e10eeb299b4479165060427086b0f76e0ef3f90d1fb55a7f88f5e00af2379af768ea2d5b29322c3a4783ec0f1d2a47171c6afe06d4f4385a751c62c37e1d85acd41ee2bbf94b8eb7afa05e5462290e5f3e5cec36c50ad933ad1a041f82890c6cdd64ea6e1582e5dd4910e73c05b4288d5e273da15fc6c7e2ad54a71ce98c879181eb449ab3ab5a43dc9954781c37528170afc35586f96c4f5ee9efc1b3d36d654099731e283224496343bd3270b9d6e6b524de3f697d790b745cb5700ba0b14c0d2901d130873156f579322c9d4fdf1b451fbafae674c7058
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110095);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/25");

  script_xref(name:"IAVB", value:"0001-B-0520");

  script_name(english:"Target Credential Issues by Authentication Protocol - No Issues Found");
  script_summary(english:"Reports protocols with valid credentials and no credential issues found.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to log in to the remote host using the provided
credentials. No issues were reported with access, privilege, or
intermittent failure.");
  script_set_attribute(attribute:"description", value:
"Valid credentials were provided for an authentication protocol on the
remote target and Nessus did not log any subsequent errors or failures
for the authentication protocol.

When possible, Nessus tracks errors or failures related to otherwise
valid credentials in order to highlight issues that may result in
incomplete scan results or limited scan coverage. The types of issues
that are tracked include errors that indicate that the account used
for scanning did not have sufficient permissions for a particular
check, intermittent protocol failures which are unexpected after the
protocol has been negotiated successfully earlier in the scan, and
intermittent authentication failures which are unexpected after a
credential set has been accepted as valid earlier in the scan. This
plugin reports when none of the above issues have been logged during
the course of the scan for at least one authenticated protocol. See
plugin output for details, including protocol, port, and account.

Please note the following :

- This plugin reports per protocol, so it is possible for
  issues to be encountered for one protocol and not another.
  For example, authentication to the SSH service on the
  remote target may have consistently succeeded with no
  privilege errors encountered, while connections to the SMB
  service on the remote target may have failed
  intermittently.

- Resolving logged issues for all available authentication
  protocols may improve scan coverage, but the value of
  resolving each issue for a particular protocol may vary
  from target to target depending upon what data (if any) is
  gathered from the target via that protocol and what
  particular check failed. For example, consistently
  successful checks via SSH are more critical for Linux
  targets than for Windows targets, and likewise
  consistently successful checks via SMB are more critical
  for Windows targets than for Linux targets.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/24");
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

function report_success(prefix, proto, db, port, user)
{
  if (lcx::check_localhost() && (proto == "SMB" || proto == "SSH"))
    return 0;

  local_var kb_prefix = prefix + proto + "/" + port;
  local_var report = '';

  auth_ok_count++;
  if (get_kb_list(kb_prefix + "/Failure")) return 0;
  if (proto == 'SSH' && lcx::has_ssh_priv_failures()) return 0;
  if (get_kb_list(kb_prefix + "*/Problem")) return 0;

  report += get_credential_description(proto:proto, port:port, user:user);

  if (empty_or_null(report))
    return 0;

  report = '\nNessus was able to log into the remote host with no privilege or access' +
           '\nproblems via the following :\n\n' + report;

  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

  return 1;
}

function report_localhost()
{
  if (!lcx::check_localhost()) return 0;
  if (!get_kb_item("Host/local_checks_enabled")) return 0;
  local_var host_level_proto = get_kb_item("HostLevelChecks/proto");
  if (empty_or_null(host_level_proto) || host_level_proto != "local") return 0;

  local_var report = 'Nessus was able to execute commands locally with sufficient privileges\n' +
                     'for all planned checks.\n\n'; 

  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);

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
  num_reported += report_success(prefix:"Host/Auth/", proto:tmp[0], port:tmp[1], user:successes[win]);
}

if (num_reported == 0) num_reported += report_localhost();

if (num_reported == 0)
{
  if (auth_ok_count > 0)
    exit(0, "Authentication successes encountered privilege, access, or intermittent failure issues.");
  else if (lcx::svc_available())
    exit(0, "No authentication successes using user supplied credentials to report.");
  else exit(0, "No local checks ports or services were detected.");
}
