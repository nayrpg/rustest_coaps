use openssl::ssl::{SslConnector, SslMethod};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

fn main() {
    println!("SSL version: {}", openssl::version::version());
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_ca_file(Path::new("./google.pem")).unwrap();
    let connector = builder.build();

    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = connector.connect("google.com", stream).unwrap();

    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut res = vec![];
    stream.read_to_end(&mut res).unwrap();
    println!("{}", String::from_utf8_lossy(&res));
}
