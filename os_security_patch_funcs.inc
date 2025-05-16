#TRUSTED 2cd971ff84d546f09d9215f41b449b4cb39b84886ab7dd367588e2ce419673394020cef627a8b6d0986f599d96e18b53b87c80176115aa0410b934c9fb798db364b729cd38a7e408c91e30ca1720b4098a3fec19abb23acd4a07a588cfdeaf9e9eb75b194f8b31b5ae9894356541e2d89280763a40b8837fbab534b43d9e2975b21cabb496402c5a7574213efc1f32f25595e632bfaabdb180e3fcfe78dfbfc84322fed343516e29dfbe2e99b550e2f61244fce0a2a87d9889ce8938020f3c2f3af78c8a8ce677331167e7564cf7b3cf997555088a93e9e866e0e6b3afdcffe0b5b2212a550a2a7c5b52c28f43907a84621874915823cd5d537a8068a386af6cdf18e4c133e80ac0170a49376d790a90491a4ce3c76493832c943def05fe050af36b21c490cb4699c52bcf6790e11d9f0a2657cb6665bb95ff7e8fd27f6d4e57aaa8f14101619a4019f66d56d0be25e4c48021143e5771cb105974aa00a7d186f234c730350403bff95ed512537a22350944689838784240a93ea4f44b0d730e2bb4c3ed76eb2cd663613bb3d92bea9dfbb1d40c7d22c9ebea846a3cbe0623c7ec77d5c6d51d7a7ba7ca47b55f902670603ceba42657909434589c9775c626959c89def152961ba3249074160c9f8d22b4df64b7a1e7cc3b8d3336b82d87122156e4ce10f6f08e2717429a8ad0bb46ae45621492e3ed455b9db96ab9abb53fd8
#TRUST-RSA-SHA256 4652e5e8f3b04a22325da359940dd49a410a1ff0baa9ab9d0c66ca8acf4f9cceb181b5fe5dfc2e39b81f1ecafedc66deea932644d03958ab89dcaa045236816c542b04defa0a25f2d003e1c6029efdd7370d35ccc1e61fe8bb92bbc2bd59644b0a524415a2bb818e0e46d5f982ae65e4a812f7fd672448ab4944efd64b45ed8eb25d5edb3ddcbf78ac9055c6e9d9d68b01011494132189589985398555421a5f849cf4d142c9a4849c3226ecd54d116af72c249ffc4aa8d2fc60e6ac025a16a26eedf9ae7d19508a1671b6d23c09fe80e5e32636aa792501ada4dd4db876b1cceea90d6aa1be3baf205fcff50517e95961f4775b3478e4b5f1dd84b002f93f68be1c40444ffa505372175644a68d3d384bed45423f45e561097c571a4ebda5707eeb4267a891793808e3700663b900dcdba08a13616e3ab64852a0e7c039687f92c89a0ca8e5aae7b8f9b1562b7525328b880b707033aa37497e66b3435c80c799103a459d0d866ae3af90f0612d327be9453154c0fdeaaacf709618de852a4f2a25ea53c2412612675e777c67520eac7140f6fc391ba206df4e8ebc170105220ad0c341892cc2604a4365bed2ca6d552cbdf24bbd0d49bea4289d369b325900fd32d3cbab70402b2cde9e1e6c5349914e2481aadbe2ee06f0f4b0fa098c70518f16b69b22c84538dcdde691a54323664aabdf7113d1cc85cce6c4574c1c237b
##
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# Revision: 1.1
#
##

namespace os_security_patch {

  ##
  # Add backslash escapes to characters that may interfere in regexes
  # for package names
  #
  # @remark It will not escape any character that is already escaped,
  #         and will trim down redundant escapes.
  #
  # @anonparam First Package name string
  #
  # @return NULL if empty or null anon param, else
  #         Anon param with every . and + preceded by \
  ##
  function regex_sanitize_package_name()
  {
    var before, after;
    before = _FCT_ANON_ARGS[0];
    if (isnull(before) || !strlen(before)) return NULL;
    after = before;
    after = ereg_replace(string:after, pattern:"\.", replace:'\\.');
    after = ereg_replace(string:after, pattern:"\+", replace:'\\+');
    after = ereg_replace(string:after, pattern:"\\\\+", replace:'\\');
    return after;
  }
}
