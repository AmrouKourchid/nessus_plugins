#TRUSTED 0640bcc11786d08955972f29faddee9144de3953647f43ddac06a3c878101f485fae80d9d4ff60b5e9d4c50aa7143b36575ab4d7c560570ae26038e76df586b2cb17c861c2519de55ab7293110e00bb3437d7335f355fbb5403cb40789e06139ba53f2599f6318d2cbe5381e47438a9a24d21bc708de4a7dab1515e79b8515e14e6e5284a0150f12a9bd6c20ce163eae8dc3773ae3e1f1835fd801a3f96f6b4175ce5aed44e50339f76790a981c0a98c89c8b850cee0b0e0e766257c3703073cfa67f7a6c52e8546e7b9e6c9e086ab2db279f98c1737bdefc75bb036709b2711291c9769d1f3af3bce4cf46fbd8f367c0c99827f43844eee049b38cc18f3a3294e35680907e0be20ce63d109426f0c72ad4dca7f37868c79a4ca115117f580918f487387cdd6c13aed10dc01fca048c2a9e98894efc441a05bfe76cfe3a44e9e4b638fe5346584f3755556d6d8c9befe1541b4c102a05c71e862c7c5840439a23621a0d3230be9494fecbc80b75c0c420cacf82f266534e4138356155b09876b7e2da02d7b19996af5d125bd8edc55e07dc66dcfb336b99a3e0fd3432c8d71682fb072b2a66177233851219580957e686ed358123b41147f836451717cf77441eb6993ba8feb6c983a34898faeb805a6549ec7d51577a5a37ed6291e9c77c1813f2c80c8f605f4b7d1d29e3d06f5b510de8e59369cfcc29c2a4a47d3119ce64b
#TRUST-RSA-SHA256 071cb265be861a388a6c62cdc1a1394deaa013aeff066a932c55daa550fbb574ae1b2c96e4ce55ae9418b959ea839d575f1135573e6b58d286a446e703fccf681fbf19cae36a3476383b708f0855ab5ca82ba53b190f427e3e47c81fc639e426b329a4b8e344cfea4ff71066c36516b48c9a495ebaa167ef959ec2ff639d5d3ffda0208912bc50bcec11eb78c8d9eebae69363b3e4ba34c1eafa1344a9f942b21e1fd81d5e3c0dcb1498d1e0e25d826c61b85e442ba2e979cc3d7a7d7a7769a6755245d7d00f9e4e114225e3b2f222feea60493e4f47ce14047bf8a31036759fb7ff20ee57c1a32b8af9298a3d9535302bba815301291cce70ed04d49045b410da1da63e8431859ed292fbe4d03bbac73bc87d846841a52afdebbf2997277abba0cc052759e9e10b754fe3f5bd94245a8b5bb81d0c1b21fd2e4f873f81d890198393425d60a8c36109d23569aa420b19df34c179caffccfe0f5ee19da0dee1ae4318b134c8a5ba2dd91375684b718d64b6120aba039b5ecd15d49eb1c46d353670b0fbf8718162ab15a4a1c1577e8b2decaa542b9d9e8cee5395656c4b68d07f9862f0f0530d78711d949abc26dc57345f6fba35adff138444793cc00be3a88504017555b1312fe74bc8161023557473e269fe09e3abe43ca72d218a0ef559c4d661c249a95a79067b3bae53a4cb3f4622f3edaccca5a7ee122c3e555c926df4
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# Revision: 0.3
#
# @NOGPL@
###

##
# Include this file (patch_add.inc) to include the minimum code
# necessary for a vulnerability plugin library to report missing
# patches / updates
##

include('agent.inc');
include('patch_globals.inc');
include('spad_log_func.inc');
include('debug.inc');

##
#
#  Namespace patch
#    Provides an encapsulated naming scope for patch supersedence functions and objects
#
##
namespace patch {
  ##
  # Logs details of a missing patch/update for a particular product
  # installation instance. Logged entries will later be processed
  # by patch_finalize.nbin for supersedence calculation. Values will
  # be validated during processing.
  #
  # @param [prod_name:string] The name of the product. The name should be as detailed as necessary so that all
  #                     findings for that prod_name are comparable for supersedence. Examples:
  #                       - "Mozilla Firefox"
  #                       - "Mozilla Firefox ESR"
  #                       - "VMware vCenter 5.5.x"
  #                       - "Oracle Java JRE 1.6.0"
  # @param [prod_family_id:integer] The global integer for the product family. Families are defined in patch_static.inc
  # @param [location:string] The location of the installation. This may be a filesystem path or the name of a package
  #                     manager. This is used to differentiate between multiple installations of the same prod_name on the
  #                     same host. Examples:
  #                       - 'C:\\Program Files\\Tenable\\Nessus'
  #                       - "/opt/nessus"
  #                       - "rpm"
  #                       - "dpkg"
  # @param [version:string|integer] The installed version of the product, used for reference in output and to uniquely
  #                     identify the installation
  # @param [missing:string|integer] The missing patch or build/version update that indicates that the prod_name is vulnerable.
  #                     This is used to compare for supersedence. The type of reference that is passed will depend on the
  #                     product; see the logic method defined for the product's family in patch_static.inc
  #                     for reference. Examples:
  #                       - 211 (build / int comparison)
  #                       - "62.0.3" (version comparison)
  #                       - "KB4033453" (Microsoft custom mapping)
  # @param [logic_id:integer] The global integer for the logic method to override the default logic method for the
  #                     family. If not provided, the default logic method for the family will be used. (optional)
  #
  # @return [list] ret[0] bool    TRUE if finding was added, else FALSE
  #              ret[1] unused  No data to return
  #              ret[2] string  An error message, if applicable. The
  #                             calling function can choose to check
  #                             the return or not.
  ##
  function log_finding(prod_name, prod_family_id, location, version, missing, logic_id)
  {
    # Disable on Agents for now
    if (agent()) return NULL;

    var err, fn = THIS_SCRIPT + ' ' + FUNCTION_NAME + '(): ';

    # Check for table
    var tables = query_scratchpad(
      "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
      _TBL_RAW_FINDINGS);
    if (tables[0]['name'] != _TBL_RAW_FINDINGS)
    {
      err = 'Table ' + _TBL_RAW_FINDINGS + ' has not been initialized.';
      dbg::detailed_log(
        name: LOGNAME,
        lvl: 1,
        src: fn,
        msg: err);
      return [FALSE, FALSE, err];
    }
    dbg::detailed_log(
      name: LOGNAME,
      lvl: 3,
      src: fn,
      msg: "Logging missing patch",
      msg_details: {
        "missing": {"lvl": 3, "value": missing}});
    query_scratchpad("INSERT or IGNORE INTO " + _TBL_RAW_FINDINGS +
      " (prod_name, prod_family_id, logic_id, location, version, missing, script_fname) " +
      " VALUES (?,?,?,?,?,?,?)",
      prod_name, prod_family_id, logic_id, location, version, missing, THIS_SCRIPT);

    return [TRUE];
  }
}
