#TRUSTED 6b3716648fb136f03a9b0f803e7d03138bf33613179d2fb704a0c92bb153c3dfe60b0bc3cfa0afc3e35d09a65cd9917b471f55a29601292fc57852d48d57bd64e61904f56cd9035e6c194d745aca961b2e501f7a5ccfd8ed04875f506c70fbce13ce6bd2dc9286c6d23fa10543b6619602d3b481a5e0e4b931ebc4c89b95d1722f4b7ad0fcba62859751e3a93c1706b05004c0de6112cb9c07a68792f48ad8b7b52501822b24ec8426ca32bad7c3df35c8359d14548f2ab74baa150c626849cc85493873f525b4340e5503368ab382941f98a763e021081a93280d0f4d09dbc38439e69f9fb955fc211fcea6c5b0498db553344481056137bbd23e65304c63c7911862dfd899d20dd12ce8f6905fcf70439dcb42e4b2e5450dbb78a273c3eea66a7acd0918d9e3cad476730670780527cb86c4779fbb70cbd38d88bae519deb973d73ff8f5a9f93ba915ad6bdbaae59d92a550311937584f7ff18b52f037a2ede17f6c072b30a782329033c5c17b7aa1aa6b2a705929057e3015af15fd108f38413a53d1f9e058a99f028fd7e38da815642e71d8b26b896aa277bf3d571329d3bc275322882dc48251de048b1d84958d4813b243c67a47c3a959ecd69f88bdacdcc76643795f19b24251f1f7d0fc8e3775197155e2e9245a1e746da1e3cbca24457f74f134b164f2f0fb62473fd60c09b6a04501f253c6efd17d94c618c111e9
#
# This NASL script was written by Martin O'Neal of Corsaire 
# (http://www.corsaire.com)
# 
# The script provides basic tftp functionality for use in other scripts...
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Corsaire 
# accepts no responsibility for any damage caused by the use or misuse of 
# this information.
#
# GPLv2
# 
# Some code was added by Michel Arboi <mikhail@nessus.org>
# Also Ron Bowes <rbowes@tenable.com> cleaned up the code in tftp_get and
# tftp_put and added support for an optional 'data' parameter in the later.
#
# Revision: 1.3
#

include("byte_func.inc");

global_var TFTP_RRQ        = 1;
global_var TFTP_WRQ        = 2;
global_var TFTP_DATA       = 3;
global_var TFTP_ACK        = 4;
global_var TFTP_ERROR      = 5;
global_var TFTP_OACK       = 6;
global_var TFTP_BLOCK_SIZE = 1024; # Use 1024 to stay under the max ip size

##
# Download a file from a remote TFTP server. 
#
# @param port The port number, probably 69.
# @param path The path of the file to download.
#
# @return The file, as a string.
##
function tftp_get(port, path)
{
  local_var s, dport, sport, block, block_num, block_size, file, response, code, error, message, option;

  set_byte_order(BYTE_ORDER_BIG_ENDIAN);

  # Create a non-connected udp port
  s = bind_sock_udp();
  if(!s)
    exit(1, "failed to bind socket");

  # Get the socket and target port from the return
  sport = s[1];
  s     = s[0];

  # Send the initial request, including our desired blocksize, to port 69
  sendto(socket:s, data:mkword(TFTP_RRQ) + path + '\x00octet\x00BLKSIZE\0' + TFTP_BLOCK_SIZE + '\0', dst:get_host_ip(), port:port);

  # Default to TFTP's default blocksize till it acknowledges our request
  # This is less than the BLOCK_SIZE constant on purpose - we don't assume
  # the server figured out the proper BLOCK_SIZE till we're done. 
  block_size = 512;
  file = '';
  while(TRUE)
  {
    # Get the response on a potentially different port
    response = recvfrom(socket:s, port:sport, src:get_host_ip(), timeout:30);
    if(!response)
      exit(1, "Failed to receive data from the TFTP server");
    dport    = response[2];
    response = response[0];

    # Read the code and remove it from the front of the packet
    code     = getword(blob:response, pos:0);
    response = substr(response, 2);

    # Take the appropriate action based on the code
    if(code == TFTP_DATA)
    {
      block_num = getword(blob:response, pos:0);
      block = substr(response, 2);
      
      file = file + block;

      # Send the acknowledgement
      sendto(socket:s, data:mkword(TFTP_ACK) + mkword(block_num), dst:get_host_ip(), port:dport);

      # When we get an incomplete block, we're finished reading - this needs
      # to be after the ACK
      if(strlen(block) != TFTP_BLOCK_SIZE)
        break;
    }
    else if(code == TFTP_ERROR)
    {
      error = getword(blob:response, pos:0);
      message = substr(response, 2);

      exit(1, "TFTP Error: " + message);
    }
    else if(code == TFTP_OACK)
    {
      option = split(substr(response, 2), sep:'\0', keep:FALSE);
      if(option[0] = 'BLKSIZE')
        block_size = int(option[1]);
      sendto(socket:s, data:mkword(TFTP_ACK) + mkword(0), dst:get_host_ip(), port:dport);
    }
    else
    {
      exit(1, "Unexpected response code from TFTP server: " + code);
    }
  }

  return file;
}

##
# Upload a file to a remote TFTP server. 
#
# @param port The port number, probably 69.
# @param path The path where the file will be put.
# @param data The file data.
##
function tftp_put(port, path, data)
{
  local_var s, dport, sport, block, block_num, block_size, file, response, code, error, message, option;

  set_byte_order(BYTE_ORDER_BIG_ENDIAN);

  # Create a non-connected udp port
  s = bind_sock_udp();
  if(!s)
    exit(1, "failed to bind socket");

  # Get the socket and target port from the return
  sport = s[1];
  s     = s[0];

  # Send the initial request, including our desired blocksize, to port 69
  sendto(socket:s, data:mkword(TFTP_WRQ) + path + '\x00octet\x00', dst:get_host_ip(), port:port);

  # Default to TFTP's default blocksize till it acknowledges our request
  # This is less than the BLOCK_SIZE constant on purpose - we don't assume
  # the server figured out the proper BLOCK_SIZE till we're done. 
  block_size = 512;
  file = '';
  while(TRUE)
  {
    # Get the response on a potentially different port
    response = recvfrom(socket:s, port:sport, src:get_host_ip(), timeout:30);
    if(!response)
      exit(1, "Failed to receive data from the TFTP server");
    dport    = response[2];
    response = response[0];

    # Read the code and remove it from the front of the packet
    code     = getword(blob:response, pos:0);
    response = substr(response, 2);

    # Take the appropriate action based on the code
    if(code == TFTP_ACK)
    {
      # Send the next block
      block_num = getword(blob:response, pos:0);

      if(block_num * block_size > strlen(data))
        break;

      sendto(socket:s, data:mkword(TFTP_DATA) + mkword(block_num + 1) + substr(data, block_size * block_num, (block_size * block_num) + block_size - 1), dst:get_host_ip(), port:dport);
    }
    else if(code == TFTP_ERROR)
    {
      error = getword(blob:response, pos:0);
      message = substr(response, 2);

      exit(1, "TFTP Error: " + message);
    }
    else
    {
      exit(1, "Unexpected response code from TFTP server: " + code);
    }
  }
}

#### Functions added by Michel Arboi <mikhail@nessus.org> ####

# The 1st function is necessary as TFTP is UDP based and not 100% reliable
# All TFTP scripts should call it to test returned data & avoid false alerts
function tftp_ms_backdoor(data, port, file)
{
 if (strlen(data) > 40 && substr(data, 0, 1) == 'MZ')
   if ('\x50\x45\x00\x00' >< data )
     report_tftp_backdoor(port: port, file: file, type: 'MS PE', data: data);
   else if ('This program cannot be run in DOS mode' >< data ||
   	    'This program must be run under Win32' >< data)
     report_tftp_backdoor(port: port, file: file, type: 'MS', data: data);
}

function report_tftp_backdoor(port, file, type, data)
{
 local_var	a, c, k;

 c = tolower(type[0]);
 if (c == 'm' || c == 'a' || c == 'e' || c == 'x') a = 'an '; else a = 'a ';

 security_hole(port: port, proto: 'udp', data: 
'
Synopsis :

The remote host has probably been compromised. 

Description :

A TFTP server is running on this port. However, while trying to 
fetch "'+ file + '", we got '+ a + type + ' executable file. 

Many worms are known to propagate through TFTP.  This is probably a
backdoor. 

Solution : 

Disinfect / reinstall the system.

Risk factor :

Critical / CVSS Base Score : 10.0
(CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C)');
 if (port == 69)
  set_kb_item(name: 'tftp/backdoor', value: TRUE);
 set_kb_item(name: 'tftp/'+port+'/backdoor', value: TRUE);

 if (strlen(data) > 0 )
 {
   k = '/tmp/antivirus/UDP/'+port;
   if (! get_kb_item(k)) set_kb_item(name: k, value: hexstr(data));
 }
 exit(0);
}

