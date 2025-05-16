#TRUSTED 02b6d1f1b4dad89623fe58ac7d5685b94a089527509fe98fbd8a2bd7bb31881a61689139ca2b4f34b0d9b5318d5462f0e8652a4627992aa46ee5ed05437d77efd3e738b21cf21964c76a6213d867da4a14bc43fd09848385ceb80008b706fba4a13a521362f99078620d00ac6a00dca0d1ec7dd5d3470f2476149622d4ca4d98447d1ec3372c307324679b03aa099e54075cd428a60e185738c918a5b2eaa4d228833db72af27c7341d41ee9e444ed4f13295de11f54c4bae87754ad888ea1b9386b75042573c4085ffeac93cfefb93d879dc4644cf24c375531483622bdcabac061faa617e686f13b3b3c222a89702ece9aa7bf5cec19e9cc0afe9d81be59a28c8db97846ae3a6d876d4d9dc8e6baa095a0a41b351738f30f1b4e117243b4ba02caba861d071dedea4613d8053c5131291270ef0760b7fee3baf8d4ee13ff77e135dfc89ee3f6f699aa6a8ff0de5e10db1f64bfa59292e78e28e333887b2b03480debd0b445b1bab38ea20864b2c2b53161f1d3331c86bb2d31b3e7da0c69c7ef56d071b613c767cd168497eaf2af159e82677558dce0bdd63cde8aff434e7396e6e8e099437e4ae04bc43aef46b0579fcd149ec58cca974f28d14e2b503493c0481f79d1052cee0cbad9d345e9cdaf7b6b9505aeda6d1571d940ff3ff3f983107e08fb2eb38f75d1f15a04bbfbb2a8e842b7cc4275ddf108ae6514097ed3f5
#TRUST-RSA-SHA256 5bc096cb9823a5544cb6e1a65186f372ab576304d3dfe465ffc4f712a44f5fc4a7a715c1dfd5e0b07cdb366861e24eaa7b39a240bcc57bf1673cf28fe8d3432b73ada15bcb0d74133129c533726a4a2ce7f6890d8ccf38733873d79c18558e6f58eebbcf75f846a60d7e10ef20f66713f150b22058dbfdede5bcc53d949e3a22e54bf02cafa7e89479208554ec3a629f9e86a49c14b1cf915a10f2e14cac8ea1b0dcb42571df32275c5b7abfbe9162694433ef4d9fc74662159d81cd2f0e5ef7605dac0aa7332f3cbaa68231760275d0e3af16c911d888f5ecc846d95c89159cdb3b00855870c8969b1ca8a063be0a56508c513deeb4b837c067cab69f4c144c3178ef575c40b05895c55fe47c25b5bea8215319e6ac46368da363d9486c2968db326a416a972ade399fe9993a34310a27db5d0d208b42a07c916578dfa89bd9323965c3649fa4dd164bcae06e7701d762609ec4e9777db3de41f5e30b76eb1c0836492183ef92ec7261a73019eab3e8209ed8001fd03dcebbba7d46b2a75f54316111c7c7416416848577e2982a34f62d762bf47adb39ed34135915abd9c29f6be200cefbfeeea44916403d60e31007b62a50aac33694e9b48ed3b392b5d49eabcf2ccb3527d98f4eaef4331c8ae3b322342532f8f77770aba5ab1d6dd8dd9c698560020c78584ac4ae25f12320d78dd9fbfd9d37bff4a4e6abb0896e6ae6eb
#------------------------------------------------------------------------------
#
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# local_detection_nix.inc
#
# Revision: 1.38
#
###

include("compat_shared.inc");
include("install_func.inc");
include("spad_log_func.inc");
include("find_cmd.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("command_builder.inc");
include("sh_commands_find.inc");
include("http.inc");
include("debug.inc");
include("lists.inc");
include("dir_allowlist_nix.inc");
include("dir_denylist_nix.inc");
include('hex.inc');
include('re.inc');
include("string.inc");
include("ssh_lib.inc");
include("ssh_func.inc");
include('validate.inc');
include('canonical_snapcraft.inc');
#pragma static(include)
include("local_detection_nix.static");
include('local_detection_nix_files.static');
include('local_detection_nix_packages.static');
include('local_detection_nix_associations.static');
#pragma static(include:false)

