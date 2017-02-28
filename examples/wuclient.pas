program wuclient;
//  Weather update server
//  Binds PUB socket to tcp://*:5556
//  Publishes random weather updates
//
{$APPTYPE CONSOLE}

uses
  Classes, SysUtils, zmq, zmq_utils;

var
  context: pointer;
  subscriber : pointer;

  //zipcode, temperature, relhumidity: integer;
  rc: integer;
  s : string;

  update_nbr: integer;

  ms: TMemoryStream;

begin
  //  Prepare our context and publisher
  context := zmq_ctx_new();
  subscriber  := zmq_socket(context, ZMQ_SUB);
  rc := zmq_connect(subscriber, 'tcp://localhost:5556');
  //rc := zmq_connect(subscriber, 'tcp://192.168.66.130:5556');
  assert(rc = 0);

  rc := zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, nil, 0);
  assert(rc = 0);

  update_nbr := 0;

  ms := TMemoryStream.Create;

//  while update_nbr < 1000 do begin
  while true do begin
    //s := zmq_recv_string(subscriber);
    //writeln(s);
    ms.Position := 0;
    zmq_recv_stream(subscriber, ms);
    //SetString(s, ms.Memory, ms.Size);
    writeln(pchar(ms.Memory));
    inc(update_nbr);
  end;

  ms.Free;
  zmq_close(subscriber);
  zmq_ctx_destroy(context);
end.
