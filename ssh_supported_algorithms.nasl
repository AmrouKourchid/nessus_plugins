#TRUSTED 22b02c3298bef0305140d28e7ad05df0da1de89bae6a4f03c8748ddf6a25c36417263f2dbeec41aec630731ff032ed00ac9c3d6f7e7e64f166d8b2ee419decf0fec454da4b72448b0ade6a7c673aebf6ed4748450d2efa44a6c31ef56596a8c5a15bedf371d1c4aae9c422dce3c9314a74e8a35a6c5628d287c245ac33af7e51e661323530295550678d770bb35388387890767da379b1ac2d88f5ae3dc7e5369f400ae83a5700d8193235745867698a6c2f82a1dad51a997d72ca1444254d62421e2c84898fe4265778a6aea99d8b3fb5a847c9aa8ae22a1b7d7059a0a4c4036f77bb3d033c469e958ebcf74b6c16499e736d9bcbffaa32fb09cba5a3ecd941c85f00cd166dd33662e9a08e2e792a559fb8993e4aa492b00fe44e70c2b35fdf70186d1201c3362fdf486ae4e5208ccf8b0eff108422603aff5e9173b1935ff6daad76afc80ea3e744a9e9514373599d61697e17668b8c01324b9c0d63d73fcbccfea5694ba0752def3ba066483e1b904b90babd9c47ffe3b9a34c6e47d1c11a526e11df47743cc8a39b8b6698a8429400a456a7aed9770c469c63487cb0784d3190ba8c1c776cd99f5ec25c0a3f0706e450e77d9cfdbcc0d1f36891cb351167cd5cea5cd0781a248cf516ee6982eb8425813050765b1ded8c3a38dd921b0a20db7f145e2cde1062a1d3cba40bf15e14fdee4f53a6aab04eb9757dca3f446f11
#TRUST-RSA-SHA256 622680744510f132080cbf75c6f983f32514918582681c6373e98ca7e9198fee1aa7ee254750d57e604d1ae6baf1518031536808fc465b1ce946a9425da53202bce3ce8e1993c03b2dd7830d99c3d95c2943503c8253aeb0bbc1987e4b4bdd8b3431863a6eb3d21dd38b42544593659127678335872766c52826edccd8d927ce4ffb5b7c29a3cbf6f437a9658edcb6702e9bf5147f4cea6c922fbc0af7ba81835e6639a62985de4191c596999f13c6d2fef22e2dccd3b01b637fbec24a485da314172ff4183155e2af168e390c7eed5d25b085d2a70f8adb84d25844c1befb8a41ad52132cbb274570112da0ecbb54f0206683fa85e628bc98ebce245a34dc0dad1a37925e2e1d8928423f701a8729832253910d545b7eadd904d61f2fceaf7f1f4333ee516009662b6433cc59513535fabc2217825f1e70c0cc515e23ea31f13dcb4348ee4b00cd51660bae3bee152b6debe6fb70b0208a81d60b8d73a0f17e7098566ff533a40dc01e7ec21bd9a1e7adc79566bf0539748b5ebc05f37c3f2a743c7012ddae3788614d2e15ff258b6c4d395559a1e2a2976c9ff74bd6fa8f68727b50500b0c64ac37e7f4447fbcf77bcbf34f03ab9fe35fb4c1ec365faf473a27e1013b4cced665936ff15858bcd02f9291079f6109bbae5540b82f748a0dbf4c9eb6db83bec7b624b37009c37d97714d194d464fa9748ec0341c2c06437be4
##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(70657);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/20");

  script_name(english:"SSH Algorithms and Languages Supported");
  script_summary(english:"Checks which algorithms and languages are supported");

  script_set_attribute(attribute:"synopsis", value:"An SSH server is listening on this port.");
  script_set_attribute(attribute:"description", value:
"This script detects which algorithms and languages are supported by
the remote service for encrypting communications.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2025 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('ssh_lib.inc');

# Get SSH port
var port = get_service(svc:'ssh', exit_on_fail:TRUE, default:22);

# Create session
var session = new sshlib::session();

# Exit of we cannot open a connection on SSH port
if (!session.open_connection(port:port))
{
  sshlib::ssh_errexit(1, 'SSH connection failed');
}

# Exit if key exchange fails or is incomplete
if (!session.complete_kex())
{
  sshlib::ssh_errexit(1, 'KEX not complete');
}

# Crypto algorithm used to negotiate with target server (client <-> server)
var c_s_crypto_algo = session.cipherset.cipher_c_to_s.crypto_alg;
var s_c_crypto_algo = session.cipherset.cipher_s_to_c.crypto_alg;

# Array of supported algorithms
var server_algos = session.kex_handler.kex_recv_namelists;

# Close the SSH connection and delete the session
session.close_connection();
delete session;

var server_algo, algo_list, algo;
var report = '';

# Build report and set relevant KLB items for each supported algo
for (server_algo in server_algos)
{
  algo_list = split(server_algos[server_algo], sep:",", keep:FALSE);

  if (!algo_list)
  {
    continue;
  }

  foreach algo (algo_list)
  {
    set_kb_item(name:"SSH/" + port + "/" + server_algo, value:algo);
  }

  report +=
    '\nThe server supports the following options for ' + server_algo + ' : ' +
    '\n' +
    '\n  ' + join(sort(algo_list), sep:'\n  ') +
    '\n';
}

report =
  '\nNessus negotiated the following encryption algorithm(s) with the server : ' +
  '\n' +
  '\n  Client to Server: ' + c_s_crypto_algo +
  '\n  Server to Client: ' + s_c_crypto_algo +
  '\n' + report;

security_report_v4(port: port, severity:SECURITY_NOTE , extra:report);