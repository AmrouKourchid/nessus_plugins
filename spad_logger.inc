#TRUSTED 204ba289f1403b8b585b85f8a4eb155abf14754892c011e9b20dbe822f6969b73f421037bac9a7a2f34d64a08bbc8b2756e351372cb9fb86be67247d882aa356e6f5e7c2bac44b53e7504a3a36519458a8cd7cf94e7af72c2b99d6248bce935f44ceb257bc7d36472020b1b1acadf0af1e7eaee471511be70c255551a4b8549800dfcab5cf8070300de79c67921566d928b85bb6b5e232c96262923e2d4bef41c0a2e529a6c145501e93444a7ba678eee35149a48dd51b186b056aabe2fe8249110f43d43454a40a3ca7fa18e088d5f9e495be79923bebaf6f44fa0b419e074a7a0610dfa848cc5ad63963abbeeeefbacc9ef5d47bc186e8d9f37414e471442a7c91131b2fc797f805bbc2e8c05f195cbc5622dfccfea1e50d80ee810720a6e0709d87fee5adb709acb752c33e42aadd92aba34f6973d8c1bb81a5a92e49ba42ee53c436b35e5d31ea8e93c49c0ec56726a634fd2810acc0d5e17d236b2266703707db3a047f00972ebc6115f9862efe52a67a6db1276fcc6372724b5fe84640a183b3c8791f22ac85aebc8df84eeb96e258a16448164e99bb2e28b48ed0ec36139dcffd3805971693cc59fee87d25d964f87ab09a8fe6bc8c116b15cf97b4a4bf2b7d9a126f6ce1c506d2af159eb27b1e33a7fc1d2b34f5bb611cb0b2288a26ac13d70b9daa807d7c60029d143e23b4e0d46f1358ddc4bf5507a075993344a8
#
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# spad_logger.inc
# Revision: 1.5
####

include("compat_shared.inc");
include("datetime.inc");
include("spad_log_func.inc");

namespace spad_logger
{
  var DEBUG = false;
  var log_name;

  ##
  # Determine if plugin debugging is enabled
  ##
  function check_plugin_debugging()
  {
    if (get_kb_item("global_settings/enable_plugin_debugging"))
      DEBUG = true;
  }

  ##
  # basic logging
  ##
  object logger
  {
    var prefix, timer;

    ##
    # Constructor
    ##
    function logger()
    {
      check_plugin_debugging();

      log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + ".log";
      if (!isnull(_FCT_ANON_ARGS[0]))
        prefix = _FCT_ANON_ARGS[0];

      timer = new("spad_logger::timer", prefix);
    }

    ##
    # Sets the prefix to be used 
    ##
    public function set_prefix()
    {
      prefix = _FCT_ANON_ARGS[0];
    } 

    ##
    # General spad_log
    ##
    public function log()
    {
      var message;

      if (!isnull(prefix))
        message = prefix + " " + _FCT_ANON_ARGS[0];
      else
        message = _FCT_ANON_ARGS[0];

      spad_log(message:message, name:log_name);
    }
  }

  ##
  # timer used for logging messages and times
  ##
  object timer
  {
    var prefix, timekeeper;

    ##
    # Constructor
    ##
    function timer()
    {
      check_plugin_debugging();

      if (!isnull(_FCT_ANON_ARGS[0]))
        prefix = _FCT_ANON_ARGS[0];
    }

    ##
    # Sets the prefix to be used 
    ##
    public function set_prefix()
    {
      prefix = _FCT_ANON_ARGS[0];
    }

    ##
    # Create new timekeeper and create initial timestamp
    #
    # @return [boolean] true if successful; false if unsuccessful
    ##
    public function start()
    {
      if (!DEBUG) return false;

      var message = _FCT_ANON_ARGS[0];
      if (isnull(message)) message = SCRIPT_NAME;

      if (!isnull(prefix))
        message = prefix + " " + message;

      timekeeper[message] = new("spad_logger::timekeeper");
      timekeeper[message].start(message);

      return true;
    }

    ##
    # Determine time difference from recorded time from start() and log
    #
    # @return [boolean] true if successful; false if unsuccessful
    ##
    public function stop()
    {
      if (!DEBUG) return false;

      var message = _FCT_ANON_ARGS[0];
      if (isnull(message)) message = SCRIPT_NAME;

      if (!isnull(prefix))
        message = prefix + " " + message;

      if (isnull(timekeeper[message])) return false;

      timekeeper[message].stop(message);
      delete(timekeeper[message]); 

      return true;
    }
  }

  ##
  # timekeeper - used by timer for keeping track of times 
  ##
  object timekeeper
  {
    var start_time;

    function timekeeper()
    {
      check_plugin_debugging();
    }

    ##
    # Set start time and log message
    #
    # @return [boolean] true if successful; false if unsuccessful
    ##
    public function start()
    {
      if (!DEBUG) return false;

      var message = _FCT_ANON_ARGS[0];

      start_time = gettimeofday();
      spad_log(message:message + ' starting...', name:log_name);

      return true;
    }

    ##
    # Set stop time, log message
    #
    # @return [boolean] true if successful; false if unsuccessful
    ##
    public function stop()
    {
      if (!DEBUG) return false;

      var message = _FCT_ANON_ARGS[0];
      var diff_time = datetime::timeofday_diff(begin:start_time, end:gettimeofday());

      spad_log(message:message + ' completed in ' + diff_time + ' seconds.', name:log_name);

      return true;
    } 
  }
}
