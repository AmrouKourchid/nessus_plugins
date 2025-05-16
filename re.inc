#TRUSTED 007ec4c9aa9210c858b62996dd0feeacdd6880b7493615fcaeacc9a7cf8cb5d692bf9249ddd23a7c016931cd68d5e2bcf6f4cbe096d4caca5af6eab9b3318fe0f3589cbfc3c31ebb56b6bac730c5c57acdfe59b2276010d549e471975181cc132ac39408f1b8b05dd5c940a92409b2bf826749bd64cf221804e0ed8bc37eac3851ecf8ae111571f7b3e6110a17a73474f9a81f521b2cc49426b1c0993cdad796b17130ae2ab8f228da00fd8ace633bc060b436349f293d14bf3c2563999f222236c98b0fb6bc00a11feb88a1b5bd20380b99b72f3d86b9141727fe227ddc6b590ae30c34143cdc47a41ef211588a2e7aeb01b4048a3e6bb4f0d2e731ece289db8aa664573c863cb2e8cc29a59a7fb2566dea88c07d59d62f42b72405b62be4c4df6f2baf5fe1de418fcdf578ff7b78d061a708b0f6b61e473fdbe640e6bc1f6e0b37f78835dbd3272cb1b089ce1527537253b527f10166368988ee77a0398edda6749d402f633882d4759a59ffe21460f00b65a90f693424b95e750e18317f42997b6e9ebfc27c8bacb10b9b3736ed80c8e4b7aa2699196f01b5c1c9d18ba9363be7f4a90d416a29fdf7c44c46ffc0bfbddd83f6771a5df8ad4d8caf74d7357738def1483b9384262dc14e4b45bb30eba43a522b4afddc584d56caebb60d7368bcac3e35915f65975d13bcc7f45671df57a6a151ffbd6e72c6666f68a69e392c
#TRUST-RSA-SHA256 af9711d38b0b8cc8cc7a3934083440d3e35423b9d695d45f05ce980eb3f713332efca6ac0409b70f55e6d578ec6dde29b0f7c76e3c63511d6ce40d15746892d4d7123eec9eb20089af88e34b894c2354c0884bd4af904666006817e4fa78c5f2aa746bcad8a214a2b5c043e4dbb6a3f5dedf16d183f243cac5f4bb3fc1ca54781d3be5b2ba26f62980ed6d605442603f7ab21b13269821852c5630a2c9017cf1252b4f9354641ce97a075e22914b79a4a55168f1ee9f35d48f40e8c2113eab2591b7500f1fcb36175065b14bb29ce5cf3c47bf8639e6625be31e760c53f3c8d45152417ba2b5a08cfa67ba4170b8c4f5369eaad069d8cad151cee58d7c9c83be8a7f77c593735ea3809ff71128a85b3b9480c5abdf25db1ae2b5c6c7281eb649bb1a67d8938170d3b0fb135c4fe8bab26b708e47e3ab823137dc2acef29990547fa746b15099b01d02c8ed1234a6a8e831a3d300304474835a6dd3550e8b1b442bce893e97711769721592af652ee2c6c6169406d5994b116c1d9e9833d767720d838294b713ef23f364cdce0c684bdce06fd75b45b96eabbca493fc1d93a05cc2466af4441780c7923879f4c6a62a90274c7c32c2fd55397e96a8cbba23170d7cd4fce550316bb00e1cf40227a37a2787e86d0db28e773494df94e9a0ac084acaa3c713f1bac5d04344b33a58a9a58619c356200638ff2fb04edacc2030449f
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# Revision: 1.3
#

include('compat_shared.inc');
include('debug.inc');
include('validate.inc');

object re {
  var match_buffer = [];

  var named_capture_groups = {};
  
  ##
  # Match pattern against the specified string.
  #
  # @param [pattern:str]    Pattern to use for matching.
  # @param [string:str]     String to match against.
  # @param [icase:bool]     Flag for case-insensitivity
  #
  # @return list of matches from pregmatch()
  #         FALSE if no matches were found
  ##
  public function match(pattern, string, icase)
  {
    var m = pregmatch(pattern:pattern, string:string, icase:icase);

    if(!isnull(m)) return m;

    return FALSE;
  }

  ##
  # Returns all matches using a line-by-line search method
  #
  # @param pattern Pattern to use for matching.
  # @param string String to match against.
  #
  # @return List containing matches, empty list if no matches
  ##
  public function match_lines(pattern, string)
  {
    foreach var line(str_to_lines(s:string))
      match_to_buffer(p:pattern, s:line);

    return return_and_clear_match_buffer();
  }

  ##
  # Extract a single group from a list of matches(multidimensional list) 
  # as a one-dimensional list. Assumes all matches have the same number
  # of groups (i.e. The same list length). 
  #
  # @param matches A multidimensional list composed of matches returned from pregmatch.
  # @param group The desired group index to return.
  #
  # @return One dimensional list containing the desired group from each supplied match.
  ##
  public function group_list(matches, index)
  {
    var ret = [], i = 0;
    foreach var match(matches)
      ret[i++] = match[index];
    
    return ret;
  }

  ##
  # Match pattern against the specified string returning named match groups.
  #
  # @param [pattern:str]    Pattern to use for matching.
  # @param [string:str]     String to match against.
  # @param [icase:bool]     Flag for case-insensitivity
  #
  # @return array of matches (see map_named_capture_groups() for more info)
  #         FALSE if no matches were found
  ##
  public function named_match(pattern, string, icase, capture_groups)
  {
    var m = match(pattern:pattern, string:string, icase:icase);

    if (!m)
      return FALSE;

    if (!empty_or_null(capture_groups))
      set_named_capture_groups(capture_groups);

    # Member variable check
    if (empty_or_null(named_capture_groups))
    {
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'The "named_capture_groups" member variable is not set. Please set via the "set_named_capture_groups" member function.');
      return NULL;
    }

    m = map_named_capture_groups(matches:m);

    if (!empty_or_null(m))
      return m;

    return FALSE;
  }

  ##
  # Map matching named capture groups array to the matching list returned from pregmatch()
  #
  # @param  [matches:list]  list of matches in the format pregmatch() returns
  #
  # @return array with matching named capture groups (e.g. { 'version': '1.3.3.7', 'build': 'b4' })
  #         NULL if an error occurred
  ##
  public function map_named_capture_groups(matches)
  {
    # Argument checks
    var checks, validation;

    checks = [
      { argname: 'matches', arg: matches, checker: validate::checker.data.list }
    ];

    validation = validate::multiple_args(checks:checks, check_all:true);
    if (!validation[0]) return NULL;

    # Member variable check
    if (isnull(named_capture_groups))
    {
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'The "named_capture_groups" member variable is not set. Please set via the "set_named_capture_groups" member function.');
      return NULL;
    }

    # Record each match
    var attribute;
    var mapped_matches = {};

    # Iterate over each capture group
    for (var index in named_capture_groups)
    {
      index = int(index);
      attribute = named_capture_groups[index];

      if (!isnull(matches[index]))
        mapped_matches[attribute] = matches[index];
    }

    return mapped_matches;
  }

  ##
  # Set the named capture groups.
  #
  # @anonparam [name_capture_groups:array] Named capture groups with the key as the matching index and the value to be used as the key in the return value
  # 
  # @return NULL always
  ##
  public function set_named_capture_groups()
  {
    # Argument checks
    var checks, validation;

    checks = [
      { argname: '_FCT_ANON_ARGS[0]', arg: _FCT_ANON_ARGS[0], checker: validate::checker.data.array }
    ];

    validation = validate::multiple_args(checks:checks, check_all:true);
    if (!validation[0]) return NULL;

    # Set member variable
    named_capture_groups = _FCT_ANON_ARGS[0];

    return NULL;
  }

  #
  # Clear the named capture groups.
  #
  # @return NULL always
  ##
  public function clear_named_capture_groups()
  {
    # Clear member variable
    named_capture_groups = {};

    return NULL;
  }


  function str_to_lines(s)
  {
    if(s == '')
      return [''];
    else
      return split(s, keep:FALSE, sep:'\n');
  }
  
  function match_to_buffer(p, s)
  {
    var m;

    if (!empty_or_null(named_capture_groups))
      m = named_match(pattern:p, string:s);
    else
      m = match(pattern:p, string:s);

    if (m) 
      insert_element(idx:max_index(match_buffer),value:m,var:match_buffer);
    
    return TRUE;
  }
  
  function return_and_clear_match_buffer()
  {
    var b = match_buffer;
    match_buffer = [];
    return b;
  }

}
