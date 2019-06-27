mod keypair_ext;
mod whitelist;

use core::convert::TryInto;
use futures::Future;
use futures::Stream;
use keypair_ext::KeyPairExt;
use quinn::Endpoint;
use rcgen::KeyPair;
use rustls::ProtocolVersion;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::runtime::current_thread;
use whitelist::Whitelist;

fn main() {
    let mut runtime = current_thread::Runtime::new().unwrap();

    let client_keypair = KeyPair::gen();
    let server_keypair = KeyPair::gen();
    let client_cert = client_keypair.sign_self().unwrap();
    let server_cert = server_keypair.sign_self().unwrap();

    let server_port = {
        // server: accept one stream on one connection, from client public key, echo
        // that stream then exit

        let mut server_tls_config = rustls::ServerConfig::new(Arc::new(Whitelist::new(&[])));
        server_tls_config.versions = vec![ProtocolVersion::TLSv1_3];
        server_tls_config
            .set_single_cert(vec![server_cert], server_keypair.as_rustls_sk())
            .unwrap();
        let server_config = quinn::ServerConfig {
            crypto: Arc::new(server_tls_config),
            ..Default::default()
        };
        let mut endpoint_builder = Endpoint::builder();
        endpoint_builder.listen(server_config);
        let (endpoint_driver, endpoint, incoming) =
            endpoint_builder.bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        runtime.spawn(endpoint_driver.map_err(|e| eprintln!("IO error: {}", e)));
        let port = endpoint.local_addr().unwrap().port();

        // listen for incoming connections until an authorized connection is recieved
        let runtime_handle = runtime.handle();
        let handle_incoming = incoming.for_each(move |(conn_driver, _conn, incoming_streams)| {
            // a quinn connection may yield multiple streams, we only accept the first one
            runtime_handle
                .spawn(conn_driver.map_err(|_| ()))
                .expect("failed to spawn connection driver");
            incoming_streams
                .take(1)
                .filter_map(|stream: quinn::NewStream| match stream {
                    quinn::NewStream::Bi(send, recv) => Some((send, recv)),
                    quinn::NewStream::Uni(_recv) => None,
                })
                .map_err(|_| ())
                .for_each(|(send, recv)| tokio::io::copy(recv, send).map_err(|_| ()).map(|_| {}))
        });

        runtime.spawn(handle_incoming);

        port
    };

    let client = {
        // client

        let mut client_tls_config = rustls::ClientConfig::new();
        client_tls_config.versions = vec![ProtocolVersion::TLSv1_3];
        client_tls_config.set_single_client_cert(vec![client_cert], client_keypair.as_rustls_sk());
        client_tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(Whitelist::new(&[])));
        let client_config = quinn::ClientConfig {
            crypto: Arc::new(client_tls_config),
            ..Default::default()
        };
        let mut endpoint_builder = Endpoint::builder();
        endpoint_builder.default_client_config(client_config); // It's also possible to set client
                                                               // config on a per-connection basis.
        let (endpoint_driver, endpoint, _incoming) =
            endpoint_builder.bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        runtime.spawn(endpoint_driver.map_err(|e| eprintln!("IO error: {}", e)));

        // connect to server, verify key
        let runtime_handle = runtime.handle();
        endpoint
            .connect(&(Ipv6Addr::LOCALHOST, server_port).into(), "noname")
            .unwrap()
            .map_err(|e| eprintln!("IO error: {}", e))
            .and_then(move |(connection_driver, connection, _incoming_streams)| {
                runtime_handle
                    .spawn(connection_driver.map_err(|e| eprintln!("IO error: {}", e)))
                    .unwrap();

                connection
                    .open_bi()
                    .map_err(|e| -> () { eprintln!("IO error: {}", e) })
                    .and_then(|(send, recv)| {
                        let len = 100_000;

                        // generatate some data
                        let to_send: Vec<u8> = (0..len)
                            .map(|n| (n % 2usize.pow(8)).try_into().unwrap())
                            .collect();

                        // send random data
                        let sender = tokio::io::write_all(send, to_send.clone());

                        // receive
                        let buf: Vec<u8> = Vec::with_capacity(len);
                        let reciever = tokio::io::read_to_end(recv, buf)
                            .map(move |(_, buf)| assert!(to_send == buf));

                        sender
                            .join(reciever)
                            .map_err(|e| -> () { eprintln!("IO error: {}", e) })
                    })
            })
    };

    runtime.block_on(client).unwrap();
}
