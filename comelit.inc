#TRUSTED 7a3b0c5f05f97b8a094856efab94a19e7f2b0b6fad0f4b52215f88cdc86bb823013485c5b87d34631f905e9f5b876a21fe564030d73d97668ac2e15012d58101ddcfb5720a1b6f4ba16de240848ca3cb33c7a88711bb8826897940933166cbe69c18dd60d3158c05dfb8c68d17254649d8bb3f2cba7ceaf930d0ef86e50a569e19776403e11a7443b91735f7525287197e45f7af43a1e63b87351468e04a6d68eab1984d4714e89f469cd678439fd1eba864980d4da7d8374c7a46eca8f7a7ded79bbe78b38b0b27db5e4f602efa0ff3b1c00be5df18affa591c64fac350e28af6ab4afb45c3da11c0d326c60d8042d46394e031a5fc709e155a8f9f8f1c357e3243cd8c73523e5169594426d19699731f8f43be26b0deda9c0e0be52d36b6b47a59a0b66bdc5b48197925a0e1df832290e308f3e8cc2656ae6ddda69dad756f54825b617e827a645242438131b5003204a2ed06fba02636e87de55885b4f542ed10209f063b6c651e73d4fa036b90b35cea8b00f39283b75f6e4f6160840fac111c60dbeccdfed1c0128ea0e2feb5ece24bbdf547af65a676d7e7e4b16b79a486a851999fca387c092ec358d82179404c933b48c713d8c9d4b0928a28282ca5176e718ab6bc8b2ee795956c8ba1a32c86e7c7ec852983c0523229c6ba7e5c88003c154c8a1bbe9c2c26a9f5171c80be6b5bd7557397d7f9f5d462490b9934b9

#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.1
#

include("compat_shared.inc");
include("byte_func.inc");

#
# This header implements various features of the ComelitViP
# Remote App:
# https://play.google.com/store/apps/details?id=com.comelit.remotevip&hl=en
#

## successful_response return values
global_var RESET_CONNECTION = 0;
global_var MISSING_DATA = 1;
global_var BAD_TYPE = 2;
global_var DEVICE_CONNECTED = 3;

## recv_expected return values
global_var RCV_NULL = 0;
global_var WRONG_TYPE = 1;
global_var CORRECT_TYPE = 2;

##
# Adds the VIP header which looks like this:
#
# [00 06][2 bytes length][2 bytes channel id][00 00]
#
# The payload is then appended and sent.
#
# @param soc - the socket to send data over
# @param channel_id - the id of the channel we are sending on
# @param payload - the payload we want to send
#
# @return void
##
function vip_send(soc, channel_id, payload)
{
  # start with the preamble
  local_var output = '\x00\x06';

  # add the length in big endian order
  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
  output += mkword(len(payload));

  # add the channel
  if (isnull(channel_id))
  {
    output += '\x00\x00';
  }
  else
  {
    output += channel_id;
  }

  # add the outro and payload
  output += '\x00\x00';
  output += payload;

  send(socket:soc, data:output);
  return;
}

##
# Reads the 8 byte frame header and then reads in the
# remaining frame. If channel_id is set then this
# function will keep consuming frames until it finds
# one on the provided channel.
#
# @param soc - the socket to recv 
# @param channel_id - the channel to receive data from
#
# @return the the message payload or NULL on failure
##
function vip_rcv(soc, channel_id)
{
  # get the preamble to find the length of the entire frame
  local_var preamble = NULL;
  local_var payload = NULL;
  do
  {
    preamble = recv(socket:soc, length:8, min:8);
    if (isnull(preamble))
    {
      return NULL;
    }

    # preamble always starts with 06 00
    if (getword(blob:preamble, pos:0) != 0x0600)
    {
      return NULL;
    }

    local_var length = getword(blob:preamble, pos:2);
    payload = recv(socket:soc, length:length, min:length, timeout:5);
    if (isnull(payload))
    {
      return NULL;
    }
  }
  while (!isnull(channel_id) &&
    getword(blob:preamble, pos:4) != getword(blob:channel_id));

  return payload;
}

##
# Create a new channel with the remote comelite device.
#
# @param soc - the socket to send data over
# @param type - the type of channel to open. ie. 'INFO' or 'CTPP'
# @param channel_id - the id of the channel we are sending on
# @param additional - extra data required to create the channel
#
# @return TRUE on success and false otherwise
##
function create_channel(soc, type, channel_id, additional)
{
  local_var payload = '\xcd\xab\x01\x00\x07\x00\x00\x00';
  payload += type;
  payload += channel_id;
  payload +='\x00';

  if (!isnull(additional))
  {
    payload += '\x00';
    payload += additional;
  }
  vip_send(soc:soc, channel_id:NULL, payload:payload);

  payload = vip_rcv(soc:soc);
  if (isnull(payload) || getword(blob:payload, pos:0) != 0xabcd)
  {
    return FALSE;
  }
  return TRUE;
}

##
# Close a channel with the remote comelite device. This function
# will consume responses from the server until it receives the
# 'Ok we closed the channel' message.
#
# @param soc - the socket to send data over
# @param channel_id - the id of the channel we are sending on
#
# @return void
##
function close_channel(soc, channel_id)
{
  local_var payload = '\xef\x01\x03\x00\x02\x00\x00\x00';
    payload += channel_id;
  vip_send(soc:soc, channel_id:'\x00\x00', payload:payload);

  # keep receiving frames until we can an ack or failure
  do
  {
    payload = vip_rcv(soc:soc);
  }
  while (!isnull(payload) && getword(blob:payload, 0) != 0x01ef);
}

##
# Receives a frame on the provided channel and verifies that
# the received frame has the correct 'type' field.
#
# @param soc - the socket to send data over
# @param channel_id - the id of the channel we are sending on
# @param expected_ack - the expected ack sequence
# @param type - the expected type (ie. 0x1800)
#
# @return returns RCV_NULL, WRONG_TYPE, or CORRECT_TYPE
##
function recv_expected(soc, channel_id, expected_ack, type)
{
  local_var payload = RCV_NULL;
  do
  {
    payload = vip_rcv(soc:soc, channel_id:channel_id);
    if (isnull(payload))
    {
      return RCV_NULL;
    }
  }
  while(!isnull(expected_ack) && getbyte(blob:payload, pos:5) != getbyte(expected_ack));

  if (getword(blob:payload, pos:0) != type)
  {
    return WRONG_TYPE;
  }
  return CORRECT_TYPE;
}

##
# A successful connection will receive three responses:
# 1800, 1840, and 1820. This function will attempt to
# receive these three items.
#
# @param soc - the socket to send data over
# @param channel_id - the id of the channel we are sending on
# @param expected_ack - the expected value of the ACK field
#
# @return one of four states:
#   1. RESET_CONNECTION: the caller should reset the CTPP connection
#   2. MISSING_DATA: missing one or more message
#   3. BAD_TYPE: An invalid type was encountered
#   4. DEVICE_CONNECTED: great success!
function successful_response(soc, channel_id, expected_ack)
{
  # A successful connection will receive three responses:
    # 1800, 1840, and 1820

  if (recv_expected(soc:soc, channel_id:channel_id,
    expected_ack:expected_ack, type:0x1800) != CORRECT_TYPE)
  {
    return RESET_CONNECTION;
  }

  local_var result = recv_expected(soc:soc, channel_id:channel_id,
    expected_ack:expected_ack, type:0x1840);
  if (result != CORRECT_TYPE)
  {
    return result;
  }

  result = recv_expected(soc:soc, channel_id:channel_id,
    expected_ack:expected_ack, type:0x1820);
  if (result == RCV_NULL)
  {
    return MISSING_DATA;
  }
  else if (result == WRONG_TYPE)
  {
    return BAD_TYPE;
  }

  return DEVICE_CONNECTED;
}

##
# This function will connect to the master. Before communicating with other
# devices, a master connection must be established.
#
# @param soc - the socket to send data over
# @param channel_id - the id of the channel we are sending on
# @param vip_address - the vip address of the master
# @param slave - the slave number used. Experience indicates all 1-15 are valid?
# @param direction - randomly generated direction values (2 bytes)
# @param seq - the initial sequence number (1 byte)
# @param ack - the initial ack number (1 byte)
# @param full_connect - TRUE if we want to establish a complete connection.
#
# @return TRUE on success and FALSE otherwise
##
function connect_to_master(soc, channel_id, vip_address, slave, direction,
  seq, ack, full_connect)
{
  local_var connect_request = '\xc0\x18';
  connect_request += direction;
  connect_request += seq;
  connect_request += ack;
  connect_request += '\x00\x11';
  connect_request += '\x00\x40';
  connect_request += mkword(rand() % 65535);
  connect_request += vip_address;
  connect_request += slave;
  connect_request += '\x00';
  connect_request += '\x10\x0e\x00\x00\x00\x00';
  connect_request += '\xff\xff\xff\xff';
  connect_request += vip_address;
  connect_request += slave;
  connect_request += '\x00';
  connect_request += vip_address;
  connect_request += '\x00\x00';
  vip_send(soc:soc, channel_id:channel_id, payload:connect_request);

  # increment the sequence number
  seq = mkbyte(getbyte(blob:seq) + 1);

  local_var connect_response = successful_response(soc:soc, channel_id:channel_id, expected_ack:seq);
  if (isnull(full_connect) || full_connect == FALSE || connect_response < DEVICE_CONNECTED)
  {
    return connect_response == DEVICE_CONNECTED;
  }

  # increment the ack number
  ack = mkbyte(getbyte(blob:ack) + 1);

  connect_request = '\x00\x18';
  connect_request += direction;
  connect_request += seq;
  connect_request += ack;
  connect_request += '\x00\x00';
  connect_request += '\xff\xff\xff\xff';
  connect_request += vip_address;
  connect_request += slave;
  connect_request += '\x00';
  connect_request += vip_address;
  connect_request += '\x00\x00';
  vip_send(soc:soc, channel_id:channel_id, payload:connect_request);

  connect_request = '\x20\x18';
  connect_request += direction;
  connect_request += seq;
  connect_request += ack;
  connect_request += '\x00\x00';
  connect_request += '\xff\xff\xff\xff';
  connect_request += vip_address;
  connect_request += slave;
  connect_request += '\x00';
  connect_request += vip_address;
  connect_request += '\x00\x00';
  vip_send(soc:soc, channel_id:channel_id, payload:connect_request);

  return TRUE;
}
