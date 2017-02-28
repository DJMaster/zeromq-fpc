unit zmq_utils;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, zmq;

function zmq_send_string(socket: pointer; s: string): integer;
function zmq_recv_string(socket: pointer): string;
function zmq_recv_stream(socket: pointer; s: TMemoryStream): integer;

implementation

function zmq_send_string(socket: pointer; s: string): integer;
var rc: integer;
    message: zmq_msg_t;
begin
  zmq_msg_init_size(@message, length(s) + 1);
  move(pchar(s)^, zmq_msg_data(@message)^, length(s) + 1);
  rc := zmq_msg_send(@message, socket, ZMQ_DONTWAIT);
  zmq_msg_close(@message);
  result := rc;
end;


function zmq_recv_string(socket: pointer): string;
var
  message: zmq_msg_t;
  size: integer;
begin
  result := '';
  zmq_msg_init(@message);
  size := zmq_msg_recv(@message, socket, 0);
  if(size = -1) then exit;
  //  memcpy(string, zmq_msg_data(&message), size);
  result := pchar(zmq_msg_data(@message));
  zmq_msg_close(@message);
end;


function zmq_recv_stream(socket: pointer; s: TMemoryStream): integer;
var
  message: zmq_msg_t;
begin
  zmq_msg_init(@message);
  result := zmq_msg_recv(@message, socket, 0);
  if(result = -1) then exit;
  s.Write(zmq_msg_data(@message)^, result);
  zmq_msg_close(@message);
end;


end.

