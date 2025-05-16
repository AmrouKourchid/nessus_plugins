#TRUSTED a559782ed503d462569db778ce2b1c1e56665216a24155f7144396d2e2d57c734422182ddd07b637a695ca8bc2f95cb52dea22bb9591b0d37c1cb8156c3971931a352bcae7856b4d86e0669ac827ff8185b0c6832525309a806d0d031d9a46c43c360e33bf21a8227af881b0b56c37861be1c5474f84ba986d2fbd3eeb899cab3726bc2bc8d69180fb0de354bc6263ea8685f877a94e794a417bd66f0d6c17c400c3eff8af6aeb31a359d1a38ae75c8fd6260fb1d527278d9d372106060eb57f5cd245f58d26487709df5450a920fc865b5a39a00c702389cd82c5b96dda0e374cbe26ea25a5831b8f6310119712992fc7ce0ac8964e25a0d895adb325a9f0856e3d40a43a7bacec8a6351e661bc7b848f44d9206c99519a5ebbc33b826030819690cf20df35afa2865fb123ea0d67d92fd8975610e7039cff2b52eef1961b2b9523c8cb25e9526fe7aa668554f96ddea499b24820cf565a77a8b6e2798d2a36fa3f5edc63ab364d67c565cbedb1c88a19e4ea895c6184e77b650a3011e9c5392b2daaa5b83d2146a94dcba197a6ad4de28b35a294421b770f3ffc4653f0ffa19699de7edfe9982686ce886d2b9b668fb35fd812cfffc641fb4ee6345bc7b263851d6e51e502507596160499cf73e79ded03b9edc72ef08542ec10b70298828e1a47706dc64c7dd08b7463e28df39da6b14981ee2c6951070b890c366ea77180
#TRUST-RSA-SHA256 58ab472a318c104629c14be9ea8fdfb9ee9da2df4544a66eab3c1db49e2080acb28c8226457203711dd3c7d9ca467a1e5deb4bfb5de378e8074818b6e14c0a6598c9f8ea6924dbf64af037bba9cd1a1baa107b63beaaf137f2ecd4269d872470e774121fcf2b656525ffdea245ef8a0b9bd3c68349c8a19bac96b1b03e489e226ec2d5720c693c98efa563a04ebe6a66aabdb96cf5c67f168d1dadfb281f041a59069e3594f80c51d20f0e01050dc322c4e1abba4b2741790ecf790126662449788476fb682f6e3db22bb180f9f7af20844c5e4bfa410afa230ce842b0101239fd27ee1d13f131613166d3278bc0c68d025d1ea404130c14e8b9354d7e0e215ab7bd7b7f8d831295400770c6866f2ad4dc20cbf421e076d3d5e45eef64ea176046ebcb0a5936095a1324a415508fa81678b86b7b4ffef31a3a9a60ca4936802e2ff5701e5b0eb1198a7ef8a9c9df996de9ae2062bcd1c91abe39bc3ed8b56969f6695f10087ff0ea4fcd25ca96d1db0b743f8b854d19ddc45dc7f145550030881548878dba873f4ccaa504dcf17cdca6cfa8d0b44831b59725eb3532ec9ffc15d917fc6634cf1cdf371765cbfc867bd5efdc3e9b4ff6705eb9ec0a561d5045a6989f44f5a38d4c340076d946030ba86aa8225126b34e6d14a53f98fc469552f6c74ab14593eb4d8aa64f799f97a26cc9f9cd9a34cf94ba76e6188f4f5ce9bb06
###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# process_on_port_parser.inc
#
# Revision: 1.02
#
# @library netstat_ss_parser.inc
#
###

include("compat_shared.inc");

##
#
#  Namespace process_on_port_parser
#    Encapsulates routines that parse netstat and ss tools output to report processes that have open network ports
#    Used by process_on_port.nasl
#
##
namespace process_on_port_parser
{
  #pragma const
  var ss_tcp_pattern = "^(tcp)\s+LISTEN\s+\d+\s+\d+\s+\[?([\*0-9a-f:\.]+)\]?:(\d+)";
  var ss_udp_pattern = "^(udp)\s+\S+\s+\d+\s+\d+\s+\[?([\*0-9a-f\:\.]+)\]?:(\d+)";
  var ss_part_two_pattern = '.+users:.+"(\\S+)",pid=(\\d+),fd=\\d+\\)\\)';
  var netstat_pattern = '^(tcp|udp)[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9]+\\.[0-9.]+):([0-9]+)[ \t]+([0-9]+\\.[0-9.]+):[0-9*]+[ \t]+(LISTEN[ \t]+)?([0-9]+)/([^ \t].*)?[ \t]*$';
  var netstat_v6_pattern = '^(tcp|udp)6?[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9a-f:]+):([0-9]+)[ \t]+([0-9a-f:]+):[0-9*]+[ \t]+(LISTEN[ \t]+)?([0-9]+)/([^ \t].*)?[ \t]*$';
  #pragma const(false)

  ##
  # Parses netstat -anp output line to retrieve network socket info
  # @param line A line of netstat -anp output
  # @return An array containing {proto:string, address:string, port:int, pid:int, executable:string}
  ##
  function parse_netstat_output_line(line)
  {
    var match_results = pregmatch(string:line, pattern:netstat_pattern);
    if (empty_or_null(match_results))  # Try IPv6 *even* if the target is IPv4
      match_results = pregmatch(string:line, pattern:netstat_v6_pattern);
    if (empty_or_null(match_results)) return NULL;

    var results = {};
    results['proto'] = tolower(match_results[1]);
    results['address'] = match_results[2];
    results['port'] = int(match_results[3]);
    results['pid'] = int(match_results[6]);
    results['executable'] = chomp(match_results[7]);

    return results;
  }

  ##
  # Parses ss -anp output line to retrieve network socket info
  # @param line A line from netstat -anp output
  # @return An array containing {proto:string, address:string, port:int, pid:int, executable:string}
  ##
  function parse_ss_output_line(line)
  {
    var match_results = pregmatch(string:line, pattern:ss_tcp_pattern + ss_part_two_pattern);
    if(empty_or_null(match_results)) match_results = pregmatch(string:line, pattern:ss_udp_pattern + ss_part_two_pattern);
    if(empty_or_null(match_results)) return NULL;

    var results = {};
    results['proto'] = tolower(match_results[1]);
    results['address'] = match_results[2];
    results['port'] = int(match_results[3]);
    results['executable'] = chomp(match_results[4]);
    results['pid'] = int(match_results[5]);

    return results;
  }
}
