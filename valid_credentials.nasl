#TRUSTED aeef2bdde334f1b449558581d0b951ba250929b19222304d293e954d5e71750e083fdb09280a314c44fee35c2a4d9b1ac9275e2b686977b0dd764c4dc3bf48017905c46a8e0f20f680ae087cb1baa8c69d067748451114d685ef73f33c4806abc7729a42d6435a03668037102c5c431de6dcaed67cbb90291a7642a8bd96f34c56e7c7e31af83520710bf67988406826596024eebfabf377e12a223d4ce6489c8c92c2f749f0b101abf02e35e7914aa0d77a843d2938e52452d8e0e52ae7badcfdce3fc0d9c977277ca0f596e24183e71408172bac55576f65cc0cf3e5f1343750ac318e4ed2e83d663702fc68cdc503affc951d9c7044596becbf26dc865418ad36ffa006002b6ad4150f9399c2bb1611d2a01316d39c8f17e649ffca2337c2502501023803dea9aae60440e3bdf7add77ed5954f8be7b2146096c02f5f88d29eca811a85baa496ea150dcdd2064321e19df6b3d7b7913ee3f408f4e51795e01695f533d7bf364568a3171afc24bf68cab5b25ecfcc3a51da2b0baf0d283e315d83b344efa0939a5f1cb19eb18fd9d2742fd1f9edea827fdcff1909fa2b9ad25b87be26a10153cec69cf102c7fa41a3b7f6d6349889358627ca3f2b308f7b53e99710dbf5d2f5f14515e735525f33d2ae5aa14c36fcce7b9db9dc082a4fc59817ad4bd734e44a2c1c690993373850bf8c1e76a2947e6ea9b737455c8d5eb845
#TRUST-RSA-SHA256 1138b917668462fe8797cf4b0aff4688920a4770a48246bd2e9fe0e021a6b156d95e9e330a7f7be06dc4c5d240a48f8801a745235531c85f68495f4be4c0b6520dd29e88e28e1d3dc9880b0413b207464276aec8b69a05d0eea131f833402bf807ade5558098d5870a645e48b1d45cb39548bba34cd553fe0ae2c97a0bb41177770f55b629a06bc397f381f090a00ec6fe20bef94a34e855f32bfe080ab79ece391589c980ebd46e0d39e97193122de4cc5cedd439f4ce4943f9c32a7b764461e81ad5942bad542eb17c16cb1316aa0b40e22728f3cc7e39c9c33d584c8f48653fdac4bc4c74ac0f094764cdf448823446bc645addac3d3839f1858a109d18df2f1db92a8437e39908d5def7eeae94a4fa4402c4df6e892bbe79a9f1e48c8896f2d37677019ab9c59f68d7ec5996baffc51a0745eab4aa50fafd96252e2e309cd73e618f1cd8991e9beb42dc03940f114a1c49ab6185152790622553b72f77ea2731aa79a765196a627c0cffe7a9cd5615efd68cf0ce730be7fc1c15fd248ebcd8b9d22aac50699e84a9b0288de55dc7098316c5d5a9d93d8748a98ac9441c0a0c282fb86ca34c89ad568b0c7ee89e7794ed0d8d2d13f8321270bae2faca79d55944d628c3d3d37d5e5a9a89c4a45f04064c8f0ae3476f6c95ef05ac17a745fc2ec42f4323818b7f67ffc6efd9de74e8e911ee087d9f06b1eaae68b1f41e3a3f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(141118);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/25");

  script_name(english:"Target Credential Status by Authentication Protocol - Valid Credentials Provided");
  script_summary(english:"Reports protocols that have valid credentials provided.");

  script_set_attribute(attribute:"synopsis", value:
"Valid credentials were provided for an available authentication protocol.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to determine that valid credentials were provided for
an authentication protocol available on the remote target because it
was able to successfully authenticate directly to the remote target
using that authentication protocol at least once. Authentication was
successful because the authentication protocol service was available
remotely, the service was able to be identified, the authentication
protocol was able to be negotiated successfully, and a set of
credentials provided in the scan policy for that authentication
protocol was accepted by the remote service. See plugin output for
details, including protocol, port, and account.

Please note the following :

- This plugin reports per protocol, so it is possible for
  valid credentials to be provided for one protocol and not
  another. For example, authentication may succeed via SSH
  but fail via SMB, while no credentials were provided for
  an available SNMP service.

- Providing valid credentials for all available
  authentication protocols may improve scan coverage, but
  the value of successful authentication for a given
  protocol may vary from target to target depending upon
  what data (if any) is gathered from the target via that
  protocol. For example, successful authentication via SSH
  is more valuable for Linux targets than for Windows
  targets, and likewise successful authentication via SMB
  is more valuable for Windows targets than for Linux
  targets.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/15");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("spad_log_func.inc");
include("cred_func.inc");
include("lcx.inc");

function report_success(prefix, proto, db, port, user)
{
  if (lcx::check_localhost() && (proto == "SMB" || proto == "SSH"))
    return 0;

  local_var kb_prefix = prefix + proto + "/" + port;
  local_var report = '';

  report = get_credential_description(port:port, proto:proto, user:user);

  if (empty_or_null(report))
    return 0;

  report = '\nNessus was able to log in to the remote host via the following :\n\n' + report;

  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

  return 1;
}

function report_localhost()
{
  if (!lcx::check_localhost()) return 0;
  if (!get_kb_item("Host/local_checks_enabled")) return 0;
  local_var host_level_proto = get_kb_item("HostLevelChecks/proto");
  if (empty_or_null(host_level_proto) || host_level_proto != "local") return 0;

  local_var report = 'Nessus was able to execute commands on localhost.\n\n';

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
  if (lcx::svc_available())
    exit(0, "No authentication successes using user supplied credentials to report.");
  else exit(0, "No local checks ports or services were detected.");
}
