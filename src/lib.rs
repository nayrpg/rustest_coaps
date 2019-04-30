use openssl::ssl::{Ssl, SslConnector, SslContextBuilder, SslFiletype, SslMethod, SslStream};
use std::error::Error;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
extern crate coap;
use coap::CoAPRequest;

struct RpgUdpServerSocket(UdpSocket);
impl RpgUdpServerSocket {
    fn new(port: u16) -> Result<RpgUdpServerSocket, Box<dyn Error>> {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], port)))?;
        Ok(RpgUdpServerSocket(socket))
    }
    fn accept(self) -> Result<RpgUdpConnectedSocket, Box<dyn Error>> {
        let mut buf = vec![0];
        let (_len, addr) = self.0.peek_from(&mut buf)?;
        RpgUdpConnectedSocket::connect_to_address(self, addr)
    }
}
impl std::fmt::Debug for RpgUdpServerSocket {
    fn fmt(&self, format: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        self.0.fmt(format)
    }
}
struct RpgUdpConnectedSocket(UdpSocket);
impl RpgUdpConnectedSocket {
    fn new(port: u16, address: SocketAddr) -> Result<RpgUdpConnectedSocket, Box<dyn Error>> {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], port)))?;
        socket.connect(address)?;
        Ok(RpgUdpConnectedSocket(socket))
    }
    fn connect_to_address(
        server_socket: RpgUdpServerSocket,
        address: SocketAddr,
    ) -> Result<RpgUdpConnectedSocket, Box<dyn Error>> {
        let socket = RpgUdpConnectedSocket(server_socket.0);
        socket.0.connect(address)?;
        Ok(socket)
    }
}
impl Read for RpgUdpConnectedSocket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.0.recv(buf)
    }
}

impl Write for RpgUdpConnectedSocket {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.0.send(buf)
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}
impl std::fmt::Debug for RpgUdpConnectedSocket {
    fn fmt(&self, format: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        self.0.fmt(format)
    }
}

pub fn run() -> Result<(), Box<dyn Error>> {
    // let mut stream = connect_to_google()?;
    // let res = send_get_request(&mut stream)?;
    // println!("{}", String::from_utf8_lossy(&res));
    // let mut stream = connect_to_local_coaps_server()?;
    accept_dtls_connection()?;

    println!("Accepted a DTLS connection! :D");
    Ok(())
}

fn connect_to_google() -> Result<SslStream<TcpStream>, Box<dyn Error>> {
    println!("SSL version: {}", openssl::version::version());
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_ca_file(Path::new("./google.pem"))?;
    let connector = builder.build();

    let stream = TcpStream::connect("google.com:443")?;
    match connector.connect("google.com", stream) {
        Err(he) => Err(Box::new(he)),
        Ok(con_stream) => Ok(con_stream),
    }
}
fn send_get_request(https_stream: &mut SslStream<TcpStream>) -> Result<Vec<u8>, Box<dyn Error>> {
    https_stream.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
    let mut res = vec![];
    match https_stream.read_to_end(&mut res) {
        Err(e) => Err(Box::new(e)),
        Ok(_len) => Ok(res),
    }
}

fn connect_to_local_coaps_server() -> Result<SslStream<RpgUdpConnectedSocket>, Box<dyn Error>> {
    println!("SSL version: {}", openssl::version::version());
    let mut builder = SslConnector::builder(SslMethod::dtls())?;
    builder.set_ca_file(Path::new("test/cacert.pem"))?;
    let connector = builder.build();

    let con_sock = RpgUdpConnectedSocket::new(8087, SocketAddr::from(([127, 0, 0, 1], 8085)))?;
    match connector.connect("127.0.0.1", con_sock) {
        Err(he) => Err(Box::new(he)),
        Ok(con_stream) => Ok(con_stream),
    }
}
fn accept_dtls_connection() -> Result<SslStream<RpgUdpConnectedSocket>, Box<dyn Error>> {
    let mut ctx_builder =
        SslContextBuilder::new(SslMethod::dtls()).expect("Failed to construct SSL Context Builder");
    ctx_builder
        .set_certificate_file(&Path::new("test/servercert.pem"), SslFiletype::PEM)
        .expect("Failed to set server certificate");
    ctx_builder.set_ca_file(Path::new("test/cacert.pem"))?;
    ctx_builder
        .set_private_key_file(&Path::new("test/serverkey.pem"), SslFiletype::PEM)
        .expect("Failed to set server key");

    let sock = RpgUdpServerSocket::new(8085).expect("Failed to bind to UDP socket 8085");
    println!("Bound to socket");
    let sock = sock.accept().expect("Failed to accept a new connection");
    println!("Accepted on UDP socket");
    let ssl = Ssl::new(&ctx_builder.build()).expect("Faild to make new SSL struct");
    Ok(ssl.accept(sock).expect("Failed during DTLS server accept"))
}
fn send_coaps_get_request(
    coaps_stream: &mut SslStream<RpgUdpConnectedSocket>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut packet = CoAPRequest::new();
    let mut buf = vec![0; 1024];
    packet.set_path("coap://127.0.0.1:8085");
    let len_sent = match packet.message.to_bytes() {
        Ok(bytes) => coaps_stream.ssl_write(&bytes)?,
        Err(_) => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "packet error",
            )));
        }
    };
    if len_sent == 0 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "Zero Written",
        )));
    }
    let len_received = coaps_stream.ssl_read(&mut buf);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_google_connection() -> () {
        connect_to_google().expect("Failed to establish TLS connection with Google");
    }
    #[test]
    fn test_google_get() -> () {
        let mut stream =
            connect_to_google().expect("Failed to establish TLS connection with Google");
        send_get_request(&mut stream).expect("Failed during HTTPS GET request to Google");
    }
    #[test]
    fn test_dtls_connection() -> () {
        connect_to_local_coaps_server().expect("Failed to connect to DTLS server");
    }
    #[test]
    fn test_coaps_get() -> () {
        let mut ssl_stream =
            connect_to_local_coaps_server().expect("Failed to connect to DTLS server");
        send_coaps_get_request(&mut ssl_stream).expect("Failed during coaps send");
    }
}
