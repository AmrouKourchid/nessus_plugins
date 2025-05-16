#TRUSTED 500d0932a8c76b4d97b9064b28ddb6d6d7280775f9dbba5e01530c69ea96be213ff9746f2360febf5629c3353a5af36c0d58c3ed17eac661836b2155534bc59a7ec1837374239ba57e42919e8cfb9671d746cdcabbd9eeb1003e73d2519b76cd4dd03ddf2104e423da41cb320cc21ffc8b448ad7d609f278536c4ce53d6a37926bac23f152795aa73a1bf5ac9e70035350df41f123ff696646c80be82c03aa43e1b976bdf6fec2e90ac17eb121fe1151ac58fd4c871754b075162f47292f0e610cf670f96556e04c392432822f691a6b5cbc88ccf18cb36c760d0a8458dee75bc15bbf3ff1045f8f00df4cb0120c3b326b79ec099f774d3ccaed7e07d75acfdbf85eb30d6d67f62f486a4988b4655c9a9f3fcb5735bf4f9f4a1a72a00d41d16ac6977ec1cdd1c2a4d6bf6f3ab02572e5bf522ffd2a47a8f47480418fb4a16602f01d610d0a4c1fa7cb52bbca5feb64425ac778515a7b1c8d187ef66c9f6d01fe076efa143965d3eea0096c51d5292c63a3cded2a49d70028647f8d5d4626fb5016c1a228288098248cb164a50539ba83148259ccccad5e6e1ad7a71e073bda1b37b2272913a611fe5d499e0dde95d4f256fbb6b7edb8ba089d03460ac31ab81f783bdd8d7b62f7b6e843d8f53c4dae63cab387d17085c006d8b214dab7f01f3b462195a8968ab0ffd008b9339a00d9169345daac7ad4742b0910033184e73293
#TRUST-RSA-SHA256 735ac1f0a9f52826bb903476d82bddadc60aef926ff715fe8ab2308920652da48411bffaa2a6c73b5fdfaad5d97ffe3a8b0ace628d084dcbd2dd656c55179c833f97f9ba20de1c1740bb95a82b28a022eadadd079738f7157e6479356bc11bebd4423f20ce9aa32b23c77d4505f337163bff3e36380b31a50550c146da59113ba6079e8d19868ae48257253347395b4897c0599658ead5c0950127832ed79510527781d0528f25dcc8c6a0edb14011538948f719d30cf22bd3cf02e489d30ee82d5fb764f285ba9296de5275f08b946b418f5b0d8eb6b54993caae3e76e726be963e8d9f2cc5c1ae58caa63ac86322d2e580dbb76b23462696fc99a4aa4f5e0a0b4cc95092b5d708c893c54c8b5abaf0b0c32deeec9b771de43f004588dbdc46c4976518a302963694211dcd6687b89272b1b7c0040d07a5cd1b22dc77e1c899ec14132e13cc65e322d87c22e484d75af0776ae2b502063fa7dfe028634fcb0516bb7c7877435a93e21ef016649a2fa070cda682d00e2d40e8bf90fcee0b373b16a2c8048d81e75558b15c4ec38209ab8dd4fb0216e92b992cebe487b36c948954a14b4bc83a768a92489fe8f9db98a584c068299eeef9022ca481e7cca2b08e1bfd8ecc39d144b5ca6c61902f719eee94356f5a3bfa89606e7e1ef4ee81ab210d5f3ae0625c6d54257a6782200010f674414c3d591c832478513c8a8736f3b0
#
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# canonical_snapcraft.inc
#
# Revision: 0.3
#
###

##
#
#   Canonical Snapcraft package manager related functions.
#
##

include('compat_shared.inc');
include('hostlevel_funcs.inc');
include('debug.inc');


namespace canonical_snapcraft {
  ##
  #  Query package info from Canonical Snapcraft package repository database.
  #
  #  This database is built in canonical_snapcraft_packages_nix_installed.nbin,
  #  which needs to be set as a dependency for this function to produce any results.

  #  @param String: pkg_name Snap package name.
  #  @returns NULL or Array: containing info regarding the package.
  ##
  function query_snapcraft_package(pkg_name)
  {
    if (isnull(pkg_name)) pkg_name = _FCT_ANON_ARGS[0];
    if (empty_or_null(pkg_name))
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'Missing required argument or "pkg_name".');
      return NULL;
    }

    return query_scratchpad(
      strcat('SELECT scheme, type, name, version, subpath, PURL from canonical_snapcraft_pkg_inventory WHERE name = ?;'),
      pkg_name
    );
  }
}

