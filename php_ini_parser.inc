#TRUSTED af29421601c333451629c4b25a216a83ec724c514e4459a3d1ce3f48102f85d6de8eee413a397ac01b4fed0e17088c92b4879f98852bca45fafea8cc627ff1c632dab7d54e29191eb3a18999ca017aedf6a6671644e22b75b864b82a6da86fac01c21b02c4b0122f319c278b8e88168d3bb899c1201e9bc84da6bc69c9420529acb834d0592b9b93b7c59bba3b9a052f14b80d7ccfdf948cc63312b55607875e2830135f2a3082a386952e9777ac2774e782bbf327f73eadf27fab4edd03e3547f98a14bf9ece3d86e133914f014aa26d311daa434818aee6248bcab95a884838e43b6c8fd0bbaaf797486edc2e589677fd60b1ba6f3bb5eb31815dc491e01d6e4e2886b43cbc7308ed8fc473ec30c8e83615b02d4b2a72aa9cc1199aa958c6bab9f51faadd25961b1d6c1d979d0c4db8302a74a26c6120ca1ffc5608bf1993bd662643a8df12fede2f58d820c7dae48a7826718f68e609c84152062affbdb75e45f54cfc884d63d438eb94531011c263dbbdc0bc8ea9712cddd5152f4f0df7cfb404e9219e2e247970834fd1d49b7830c3fc93b7550c452dcff5f51d0ffee9eff77d13066540193039ae625ec57e319207e2d612385b337ae623f590e3c82b28409087d165906bf946a113b6010edb724f73939d3e73380abc9083f6b0eea894921e911791284c1b9569c8e9830992f390e36a7a3ee463f44aed180f60b38cd
#TRUST-RSA-SHA256 8de6120978a8ba27c383335eb200842808ebfa21211bc643eadba86a0aa02cd8938a564a13f20a9a87bdffc5e49f0d9c7e44cee105c9cc9f06c743222dd83b027d403ed1738234af48b15ee01861df4a392dff772c96501b0f25a2c685843a362defd973d9936fb812477a092c91db64c830d86f625202cd61861536a6b972bb3c89f3da0450857fd14a526490f53f82ae82791cf0c66eadb75f747ef19e09383956a1babfe9fad2c84948ad7cffe75b4188a42277cb4e4e5cee1c6cb5b96013ed4190063393ac16d15c9173838154a4c87a1eea626a0111017135f0ba1c9e61835867ee61da010582f777cdf6e1234cce61ae667a2657e54315c79dc2b02d32c80be80672d78ef902102e97585241e605a094eeaef942cc4aabedd7e2ebf8c642f30c537199d0697f733054d35f3d42a097a0e193629c6afa7c470fcea30d914670df26bc379aca90f848d6438c2e16e1630753b5d41f323cc52a5daaebba8991a31a57501b111ae7dfbfb36b53cf302ca8f8f0157909386f7731fed06af61e4cac638d35c012ccef617b4435b7f1b7918753394b59dc39286978fdb96c7f8814f967e1bfe5251459fac686cbcd57f0ffa9db660a7ba3fc7fabef95065f2918be6be7a83b67954dc45c1ea5bb4bfe31f851a36d875d5d9512c0c7705c570608a12dfcc3b30d25fcca659437caf794b1a21859221f05666d8ac5f1db591d286b
##
# (C) Tenable, Inc.
##

include('compat_shared.inc');
include('debug.inc');

object php_ini_parser
{
  var parsed_ini = {};
  var current_section = "";

  ##
  # Constructor. Parses the contents of the php.ini file.
  #
  # @param anon The contents of the php.ini file.
  ##
  function php_ini_parser()
  {
    this.parse_ini(contents:_FCT_ANON_ARGS[0]);
  }

  ##
  # Getter for the parsed_ini property.
  #
  # @return The parsed ini file.
  ##
  public function get_ini()
  {
    return this.parsed_ini;
  }

  ##
  # Parses an additional ini file. Overwrites any existing values.
  #
  # @param contents The contents of the ini file.
  ##
  public function add_ini_file(contents)
  {
    this.parse_ini(contents:contents);
  }

  ##
  # Parses an entire ini file, line by line.
  #
  # @param contents The contents of the ini file.
  ##
  function parse_ini(contents)
  {
    foreach var line (split(contents, keep:FALSE))
    {
      if (this.line_is_comment(line:line)) continue;
      if (this.line_is_empty(line:line)) continue; 
      
      this.parse_line(line:line);
    }
  }

  ##
  # Parses a single line of the ini file.
  #
  # @param line The line to parse.
  #
  # @return TRUE if the line was successfully parsed, FALSE otherwise.
  ##
  function parse_line(line)
  {
    if(this.try_to_parse_section_line(line:line)) return TRUE;

    if(this.try_to_parse_key_value_line(line:line)) return TRUE;
    
    dbg::detailed_log(lvl:2, msg:"Failed to parse PHP ini line: " + line);

    return FALSE; # Unknown line type
  }

  ##
  # Checks if the line is a comment.
  #
  # @param line The line to check.
  #
  # @return TRUE if the line is a comment, FALSE otherwise.
  ##
  function line_is_comment(line)
  {
    if (ereg(pattern:"^\s*;", string:line)) return TRUE;
    return FALSE;
  }

  ##
  # Checks if the line is empty.
  #
  # @param line The line to check.
  #
  # @return TRUE if the line is empty, FALSE otherwise.
  ##
  function line_is_empty(line)
  {
    if (ereg(pattern:"^\s*$", string:line)) return TRUE;
    return FALSE;
  }

  ##
  # Tries to parse a section line not knowing if it is a section line.
  #
  # @param line The line to parse.
  #
  # @return TRUE if the line was successfully parsed, FALSE otherwise.
  ##
  function try_to_parse_section_line(line)
  {
    var match = pregmatch(pattern:"^\s*\[(.*?)\]", string:line);
    if(empty_or_null(match))
      return FALSE;
    
    this.current_section = match[1];
    
    if(!this.parsed_ini[this.current_section])
      this.parsed_ini[this.current_section] = {};
    
    return TRUE;   
  }

  ##
  # Tries to parse a key value line not knowing if it is a key value line.
  #
  # @param line The line to parse.
  #
  # @return TRUE if the line was successfully parsed, FALSE otherwise.
  ##
  function try_to_parse_key_value_line(line)
  {
    var match = pregmatch(pattern:"^\s*([^=]+)\s*=\s*(.*)$", string:line);
    if(empty_or_null(match))
      return FALSE;
    
    this.parsed_ini[this.current_section][trim(match[1])] = trim(trim(match[2]), chars:'"');

    return TRUE;
  }
}
