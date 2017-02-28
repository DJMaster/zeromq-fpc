program wuserver;
//  Weather update server
//  Binds PUB socket to tcp://*:5556
//  Publishes random weather updates
//
{$ifdef MSWINDOWS}
  {$APPTYPE CONSOLE}
{$endif}


uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  SysUtils, zmq, zmq_utils;

var
  context: pointer;
  publisher: pointer;

  zipcode, temperature, relhumidity: integer;
  rc: integer;
  s : string;

begin
  //  Prepare our context and publisher
  context := zmq_ctx_new();
  publisher := zmq_socket(context, ZMQ_PUB);
  rc := zmq_bind(publisher, 'tcp://*:5556');
  assert(rc = 0);

  Randomize;
  while True do begin
    zipcode := Random( 100000 );
    temperature := Random( 215 ) - 80;
    relhumidity := Random( 50 ) + 10;
    s := Format('%05d %d %d', [zipcode, temperature, relhumidity]);
    writeln(s);
    zmq_send_string(publisher, s);
  end;

  zmq_close(publisher);
  zmq_ctx_destroy(context);
end.
