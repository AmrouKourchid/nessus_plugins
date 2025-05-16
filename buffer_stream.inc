#TRUSTED 1d72366c8fca58a472dcb8562033037aff8f98eb9e030a691b6245637e142edca91c46c85c29eb00a918fe8a2cf6682b57c15bbd925001e9608d145d301f8cfb16d57c428ec2b5cc19f839e6adf84c66c379dfc25c4b960066f39f3d0181e9cc430fb0ee6a33f89617dd310626e210a6cf623b173d49de46ab1139ecdd7b7ff413bcd14aa46401ed64dd0f5ebb985b8a48c3f56cffcaf57d3144e5da5083e2ada4408cab99dc44417569dffe26070753d6a99824a6b29949a1ceed20e0c5865dee548e4bd61ab37506e7825f74fd1342836a72d99cea3d9139d17fd5cf6f7756fda2639fcfefa23a72dd94f0ead969fc39e7303e182ff274680b1a235db35f8a77ba05bac0ff3bb33060035eb3322977dbaf31da5ff7de5678131d13e2d7ced0fddfbcdeb5190875eafac78bf66beae20e6e84f186b3480709493b7a8520efe629e8db09bca1d696b96e688f1523c116b6cae9df1c0adb13f42aff152347e3c6cfe845ad7307a481b52ab7da34129b3593b2970e9809fb1fe01776b9ff38aad3804a9681a367251a49deec4853aa6ae50c60668027be7a8ec15888a4c764a204b60dcea0e418c8761ca16ba6ab9afdf8d9e3567c5692faeeeae6e2c6a584ba0a18202d91460064c4680a8fe64b140fd9322a4d6f56fcf89b0e660a8a1e188a14d4634b32909d6b2b2a21f0a96d21f01660a756c6577d83aa728cef2d136fa155
##
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# buffer_stream.inc
# Revision: 1.3
#
# This include allows reading of multiple files, network, or string data 
#  in a windowed stream for parsing
#
##

global_var NSBS_STREAM_BUFFER,NSBS_STREAM_TYPE,NSBS_STREAM_CONTENT,
NSBS_STREAM_BUFFER_POINTER,NSBS_STREAM_FILE,NSBS_STREAM_STRING,
NSBS_STREAM_NETWORK, NSBS_STREAM, NSBS_STREAM_BLOCK_SIZE;

NSBS_STREAM = make_array();

NSBS_STREAM_TYPE = "type";
NSBS_STREAM_CONTENT = "content";
NSBS_STREAM_BUFFER_POINTER = "pointer";
NSBS_STREAM_BLOCK_SIZE = "len";

NSBS_STREAM_FILE    = 1;
NSBS_STREAM_STRING  = 2;
NSBS_STREAM_NETWORK = 3;

##
# Initialize the stream 
#
# @param [type:int] A constant ID defines in the header
# @param [content:object] the content location. string|file|socket
# @param [block_size:int] the size of the sliding window [default:4096]
# @param [id:string] a unique identifier for this stream
#
# @return 0
##
function nsbs_streamInit(type, content, block_size, id)
{
  local_var buf, nsbs_stream_settings, fd;

  if (isnull(block_size)) block_size = 4096;

  if (isnull(content))
    exit(1, "No content supplied to read.");

  if(isnull(id)) 
    exit(1, "No id supplied for this stream.");

  if(typeof(type) == "function")
  {
    #do nothing
  }
  else if (type == NSBS_STREAM_FILE)
  {
    fd = file_open(name:content, mode:"r");
    buf = file_read(fp:fd, length:10);
    if (isnull(buf))
    {
      file_close(fd);
      exit(1, "File descriptor supplied was not able to read the file.");
    }
    content = fd;
    
  }
  else if (type == NSBS_STREAM_NETWORK)
  {
    if (isnull(get_source_port(content)))
      exit(1, "Socket supplied to stream is not a valid socket.");
  }
  else if (type == NSBS_STREAM_STRING)
  {
    if (typeof(content) != "data" && typeof(content) != "string" )
      exit(1, "String supplied to stream is not a valid string.");
  }
  else
  {
    exit(1, "Invalid type defined for stream.");
  }

  nsbs_stream_settings = make_array(
    NSBS_STREAM_TYPE, type,
    NSBS_STREAM_CONTENT, content,
    NSBS_STREAM_BUFFER_POINTER, 0,
    NSBS_STREAM_BLOCK_SIZE, block_size
  );
  NSBS_STREAM[id] = nsbs_stream_settings;

  return 0;
}

##
# Read in a block of content from the stream
#
# @param [id:string] id for the stream
#
# return string block of content or NULL if error reading
##
function nsbs_streamRead(id)
{
  local_var buf;

  if (NSBS_STREAM[id][NSBS_STREAM_TYPE] == 0)
    exit(1, "nsbs_streamInit was not called or failed to initialize a type.");

  if (typeof(NSBS_STREAM[id][NSBS_STREAM_TYPE]) == "function")
  {
    return NSBS_STREAM[id][NSBS_STREAM_TYPE](id:id);
  }
  else if (NSBS_STREAM[id][NSBS_STREAM_TYPE] == NSBS_STREAM_FILE)
  {
    buf = _nsbs_readfrom_file(id:id);
    if (isnull(buf)) file_close(NSBS_STREAM[id][NSBS_STREAM_CONTENT]);
    return buf;
  }
  else if (NSBS_STREAM[id][NSBS_STREAM_TYPE] == NSBS_STREAM_NETWORK)
  {
    return _nsbs_readfrom_network(id:id);    
  }
  else if (NSBS_STREAM[id][NSBS_STREAM_TYPE] == NSBS_STREAM_STRING)
  {
    return _nsbs_readfrom_string(id:id);
  }
  else
  {
    exit(1, "Invalid type defined for stream.");
  }

  return NULL;
}

##
# seek forward in reading a buffer
#
# @param [offset:int] offset to start reading
# @param [id:string] id for the stream
#
# @return NULL
##
function nsbs_seek(offset, id)
{
  if (isnull(id)) exit(1, "No id suppled to function nsbs_seek");

  if (NSBS_STREAM[id][NSBS_STREAM_TYPE] == 0)
    exit(1, "nsbs_streamInit was not called or failed to initialize a type.");
  else if (NSBS_STREAM[id][NSBS_STREAM_TYPE] == NSBS_STREAM_NETWORK)
    exit(1, "Can not seek on network streams.");

  NSBS_STREAM[id][NSBS_STREAM_BUFFER_POINTER] = offset;
}

##
# function allows the changing of block size
# 
# @param [block_size:int] window size for reading
# @param [id:string] the stream identifier
#
# @return NULL
##
function nsbs_setBlockSize(block_size, id)
{
  if (isnull(block_size) || block_size < 1)
    exit(1, "Invalid block size supplied for nsbs_setBlockSize.");

  NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE] = block_size;
}

##
# get the block size for the stream
#
# @param [id:string] the stream identifier
#
# @return int block size
##
function nsbs_getBlockSize(id)
{
  return NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE];
}

##############################################
#------------ Private Functions -------------#
##############################################

##
# private function
# read a buffer in from the file stream
#
# @param [id:string] stream id
#
# @return string buffer of content
#   NULL if end of buffer
##
function _nsbs_readfrom_file(id)
{
  local_var buf;

  file_seek(
    fp:NSBS_STREAM[id][NSBS_STREAM_CONTENT],
    offset:NSBS_STREAM[id][NSBS_STREAM_BUFFER_POINTER]
  );
  NSBS_STREAM[id][NSBS_STREAM_BUFFER_POINTER] += NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE];

  buf = file_read(
    fp:NSBS_STREAM[id][NSBS_STREAM_CONTENT], 
    length:NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE]
  );

  if (strlen(buf) < 1) buf = NULL;

  return buf;
}

##
# private function
# read a buffer in from a string
# 
# @param [id:string] stream id
#
# @return string buffer of content
#   NULL if end of buffer
##
function _nsbs_readfrom_string(id)
{
  local_var buf;

  buf = substr(
    NSBS_STREAM[id][NSBS_STREAM_CONTENT], 
    NSBS_STREAM[id][NSBS_STREAM_BUFFER_POINTER],  
    NSBS_STREAM[id][NSBS_STREAM_BUFFER_POINTER]+(NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE]-1)
  );
  NSBS_STREAM[id][NSBS_STREAM_BUFFER_POINTER]+= NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE];
  if (strlen(buf) < 1) buf = NULL;

  return buf;
}

##
# private function
# read a buffer in from a socket
#
# @param [id:string] stream id
#
# @return string buffer of content
#   NULL if end of buffer
##
function _nsbs_readfrom_network(id)
{
  local_var buf;

  if (isnull(NSBS_STREAM[id])) return NULL;

  if (NSBS_STREAM[id]["socketSet"])
  {
    if (socket_pending(NSBS_STREAM[id][NSBS_STREAM_CONTENT]))
    {
      buf = recv(
        socket:NSBS_STREAM[id][NSBS_STREAM_CONTENT],
        length:NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE]
      );
    }
    else
      return NULL;
  }
  else
  {
    buf = recv(
      socket:NSBS_STREAM[id][NSBS_STREAM_CONTENT],
      length:NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE]
    );

    NSBS_STREAM[id]["socketSet"] = TRUE;
  }

  return buf;
}

