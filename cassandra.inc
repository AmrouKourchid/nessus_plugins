#TRUSTED 9dce614561e0eb1dc5bc1d880d274da69a17d9f2f39bcc0e8abbace1c54092bb4964b1880bc87d96f39496605c15318590475a8a11a6e9c77a30e39a1d4fc5b47e4c4d378abde595c031e0fdf0abed4453e66e8664abbaef9e0571535e3acc288c472f5cf05c83e92b532aec005593346fa614d674751fae53cbb0919adc2b64ad2a56a556455a93b0bdd23446b45ec5dfaff93c7fe3f3d4c00620719697f9fc46882f18152dd0d3d9ae6008b6943d494f72bd2cc14ef8a2ef73dada24ceac5088ca1b3cfa265b513c1514c600ec68238916c80d2a2b1ededb134635b2da11059428e43c8c70091cea6bc36ece13c337ec9a602bc14a51d7a5604b28ec92e1b5d8f8311ee799ac94d8fee4813f748d136ff76311246d63f8621d9a0ec7b9f230f89b21dfa0c975ff0a4cac9f8788ae468a2da7bde690565377853e54f766918efa04fadfe7f58f3954f00738dde263bc55d884b41beabefdae22106bda5ad5a5b9c7a4753e7909bfd774e629da2524d37b476468588eb5e0432cd1da3fa23935d5b347f4682306014b4b66bb01755ccc0457cbc2581c2194f26db2ede07c02ece4f45002752fdef2fc0fed456299671adad5c26ff8126581fb615c864c1a68775f4a58b5226822d31100ca906e5823a0ce6cc92ab9706880743baa6d534f76127be14a2cfc9a377f26ad1c39a5c976c809e880598cf7eac0552e05f353ae5c93
#TRUST-RSA-SHA256 810d3f04aaebcbb5c6f93b45030999e97b3df652f9348fe7c127cadbf745a90164ba6629797c5a34aa78811bb1b4bea600bae9b99a9a468e070f00639eff0213c91b3a12aafafda9fa7ec96212a3772d28436ff31804b44bcd5ce682fffe2ed54ad06afd360d7b7ae24d601e294de24e9a946ee7e6fef961dc6f10940fd25826a860c133445592acfff72d25449c0c6ccdd8fd1157fea195afc61c78ef02c51d176e5e6d9e9e00e242911030beeff28fc4e63a000998bf8ef9837973dafdbeffb3aaae6f1df3ad3998703ef1c8f32cdb1a4628d513db2c7f5c71d179330748fb59bb981fca056f804e07419b436c2d20ce5299c1ada70c14cc68ed8a5cc60c6d17b2d2de2f42769e8c783cb9390381a68a3e9e4bd235b75da3f5e77e4d6bb00347bb71595365336dabfb60f6947ca54f707eddb27279984ba4d4060f6e8eaa96adc89609f4a8126eac2bb08c6cfc3278b2e9629d38c9b9e457e93c02203df6a400539cbc026c312cebcb901e4f4a872c3a95706c3ac8d11d756ef6b7ba87d8861de5f11d7d275ca72dfa479ff8f54d7567a119d4ead9cd74612a8560df041827be50846eab068a0a074be12577fbaad99e1714129bd54ee67bd9656b5259c78a535db9c5149b8d2b9f958087664cd7f03cd20c1af7c2ce9318d8b566148fccba85f9dedcfe02364f7fe658e40e4daf0f7e7b9c2f60bb17afa5e45ec1eed9226d
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# cassandra.inc
#
# Revision: 1.4
#
# @include misc_func.inc
###

include("compat_shared.inc");
include("spad_log_func.inc");
include("debug.inc");
include("hostlevel_funcs.inc");

##
# Runs cqlsh with appropriate login information
# @remark info_connect() must be called before using this function!
# @remark Plaintext authorization methods will reject attempts to use this command
#
# @param cassandra_home path to Cassandra installation
# @param command cqlsh command to execute
# @return NULL if missing arguments, or
#         info_send_cmd() results of the assembled command
##
function cqlsh_send_cmd(cassandra_home, command)
{
  var cqlsh_path, cqlsh_user, cqlsh_pass, constructed_command, test_response;
  if(empty_or_null(cassandra_home))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "cqlsh_send_cmd(): missing required argument 'cassandra_home'");
    return NULL;
  }
  if(empty_or_null(command))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "cqlsh_send_cmd(): missing required argument 'command'");
    return NULL;
  }
  test_response = get_kb_item('Testing/Cassandra/test_response');
  if(!empty_or_null(test_response))
    return test_response;

  cqlsh_path = cassandra_home + '/bin/cqlsh';
  constructed_command = cqlsh_path + ' ';

  # Do not execute commands with password arguments on the command line! Those will be logged.
  # For now rely on .cassandra/cqlshrc being configured.
  #cqlsh_user = get_kb_item('Secret/Cassandra/user');
  #cqlsh_pass = get_kb_item('Secret/Cassandra/password');
  #if (!empty_or_null(cqlsh_user) && !empty_or_null(cqlsh_pass))
  #{
  #  constructed_command += '-u ' + cqlsh_user + ' -p ' + cqlsh_pass + ' ';
  #}
  constructed_command += '-e \'' + command + '\'';
  #return info_send_cmd(cmd:constructed_command, redact:cqlsh_pass, cleartext_abort:TRUE);
  return info_send_cmd(cmd:constructed_command);
}

##
# Parse a cassandra.yaml output into an array of its relevant settings
# @anonparam [1st:string] Contents of the cassandra.yaml file
# @return NULL if missing argument, or
#         array containing parsed entries
##
function parse_cassandra_yaml()
{
  var cassandra_yaml = _FCT_ANON_ARGS[0];
  if (empty_or_null(cassandra_yaml)) return NULL;
  
  var yaml_key, match, parsed_results = {};
  var fetch_keys = [
    'cluster_name',
    'authenticator',
    'authorizer',
    'role_manager',
    'storage_port',
    'ssl_storage_port',
    'listen_address',
    'listen_interface',
    'start_native_transport',
    'native_transport_port',
    'native_transport_port_ssl',
    'start_rpc',
    'rpc_address',
    'rpc_interface',
    'rpc_port'
  ];
  
  foreach yaml_key (fetch_keys) 
  {
    match = pregmatch(
      string:  cassandra_yaml, 
      pattern: strcat('\\n\\s*', yaml_key, '\\s*:\\s*[\'\"]?([^\'\"]+?)[\'\"]?\\s*(?:\\n|$)')
    );
    if(!empty_or_null(match) && !empty_or_null(match[1]))
      parsed_results[yaml_key] = match[1];
  }

  return parsed_results;
}
