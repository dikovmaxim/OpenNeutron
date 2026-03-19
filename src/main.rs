use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;
use std::io::Result;
use std::collections::HashMap;
use rustls::{ServerConfig};
use std::sync::Arc;

fn main() -> Result<()> {

    let listener = TcpListener::bind("0.0.0.0:2525")?;

    //while true
    loop {
        //on accept, open a stream
        let (mut stream, _) = listener.accept()?;
        //write to the stream a greeting
        stream.write_all(b"220 localhost ESMTP ready\r\n")?;
        stream.flush()?;

        //read from the stream until we get a newline
        let mut buffer = [0; 1024];
        let mut email_fsm = EmailReceivingFSM::new();
        loop {
            let bytes_read = stream.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            email_fsm.handle_command(&buffer[..bytes_read], &mut stream)?;
        }
        email_fsm.parse_body();
        let email = email_fsm.get_email();
        println!("Received email: {:?}", email);

    }
    
    return Ok(());
}

struct TLSRecordHeader {
    content_type: u8,
    legacy_version: u16,
    length: u16, //payload length
}

impl TLSRecordHeader {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 {
            return None;
        }
        let content_type = bytes[0];
        let legacy_version = u16::from_be_bytes([bytes[1], bytes[2]]);
        let length = u16::from_be_bytes([bytes[3], bytes[4]]);
        Some(TLSRecordHeader {
            content_type,
            legacy_version,
            length,
        })
    }
}

struct TLSRecord {
    content_type: u8,
    legacy_version: u16,
    length: u16, //payload length
    payload: Vec<u8>,
}

impl TLSRecord {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 {
            println!("Not enough bytes for TLS record header");
            return None;
        }
        let header = TLSRecordHeader::from_bytes(bytes)?;
        if bytes.len() < (5 + header.length as usize) {
            println!("Not enough bytes for TLS record payload");
            return None;
        }
        let payload = bytes[5..(5 + header.length as usize)].to_vec();
        Some(TLSRecord {
            content_type: header.content_type,
            legacy_version: header.legacy_version,
            length: header.length,
            payload,
        })
    }
}

fn parse_tls_record(packet: &[u8]) -> Option<TLSRecord> {
    if packet.len() < 5 {
        println!("Packet too short to be a TLS record");
        return None;
    }
    let header = TLSRecordHeader::from_bytes(packet)?;

    println!("Parsed TLS Record Header: content_type={}, legacy_version={}, length={}", header.content_type, header.legacy_version, header.length);

    if packet.len() < (5 + header.length as usize) {
        println!("Packet too short for TLS record payload");
        return None;
    }
    let payload = packet[5..(5 + header.length as usize)].to_vec();

    println!("Parsed TLS Record: content_type={}, legacy_version={}, length={}", header.content_type, header.legacy_version, header.length);

    Some(TLSRecord {
        content_type: header.content_type,
        legacy_version: header.legacy_version,
        length: header.length,
        payload,
    })
}




#[derive(Debug, Clone)]
struct Email {
    from: String,
    to: Vec<String>,
    raw_data: String,
    content: String,
    headers: HashMap<String, String>,
}

impl Email {
    fn new() -> Self {
        Email {
            from: String::new(),
            to: Vec::new(),
            raw_data: String::new(),
            content: String::new(),
            headers: HashMap::new(),
        }
    }

    fn to_string(&self) -> String {
        let mut email_string = format!("From: {}\r\n", self.from);
        for recipient in &self.to {
            email_string.push_str(&format!("To: {}\r\n", recipient));
        }
        email_string.push_str(&format!("Headers: \r\n"));
        for (key, value) in &self.headers {
            email_string.push_str(&format!("{}: {}\r\n", key, value));
        }
        email_string.push_str(&format!("\r\n{}\r\n", self.content));
        return email_string;
    }
}


enum EmailReceivingState {
    WaitingForEhlo,
    WaitingForMailFrom,
    WaitingForRcptTo,
    WaitingForData,
    ReceivingData,
    WaitingForQuit,

    //Tls-related states
    WaitingForStartTls,
}

struct EmailReceivingFSM {
    state: EmailReceivingState,
    email: Email,
}

impl EmailReceivingFSM {
    fn new() -> Self {
        EmailReceivingFSM {
            state: EmailReceivingState::WaitingForEhlo,
            email: Email::new(),
        }
    }

    fn handle_command(&mut self, packet: &[u8], stream: &mut TcpStream) -> Result<()> {
        let command = String::from_utf8_lossy(packet).to_string().to_lowercase();
        //println!("Received command: <{}>", command.trim());
        match self.state {
            EmailReceivingState::WaitingForEhlo => {
                if command.contains("ehlo") {
                    self.state = EmailReceivingState::WaitingForMailFrom;
                    stream.write_all(b"250-127.0.0.1\r\n250-STARTTLS\r\n250 OK\r\n")?;
                    stream.flush()?;
                }
            }

            //Tls handling
            EmailReceivingState::WaitingForStartTls => {
                //here we start getting bytes from the stream and decryptt them as tls packets
                let mut packet_buffer = [0; 1024];
                let bytes_read = stream.read(&mut packet_buffer)?;
                if bytes_read == 0 {
                    //tls interrupted, go back to waiting for email
                    self.state = EmailReceivingState::WaitingForMailFrom;
                }

                if let Some(tls_record) = parse_tls_record(&packet_buffer[..bytes_read]) {
                    println!("Received TLS record with content type: {}", tls_record.content_type);
                    // Here you would typically handle the TLS record, e.g., by decrypting it and processing the contained SMTP commands.
                    // For simplicity, we will just print the content type and ignore the actual TLS processing.
                } else {
                    println!("Failed to parse TLS record");
                }



            }

            EmailReceivingState::WaitingForMailFrom => {

                // Handle STARTTLS command
                if command.contains("starttls") {
                    self.state = EmailReceivingState::WaitingForStartTls;
                    stream.write_all(b"220 Ready to start TLS\r\n")?;
                    stream.flush()?;
                }

                if command.contains("mail from:") {
                    self.state = EmailReceivingState::WaitingForRcptTo;

                    //extract between the < and > with regex
                    let re = regex::Regex::new(r"<(.*?)>").unwrap();
                    if let Some(caps) = re.captures(&command) {
                        self.email.from = caps.get(1).unwrap().as_str().to_string();
                    }

                    stream.write_all(b"250 OK\r\n")?;
                    stream.flush()?;
                }
            }
            EmailReceivingState::WaitingForRcptTo => {
                if command.contains("rcpt to:") {
                    self.state = EmailReceivingState::WaitingForData;

                    //extract multiple email addresses between the < and > with regex
                    let re = regex::Regex::new(r"<(.*?)>").unwrap();
                    for caps in re.captures_iter(&command) {
                        let email_address = caps.get(1).unwrap().as_str().to_string();
                        self.email.to.push(email_address.clone());
                    }

                    stream.write_all(b"250 OK\r\n")?;
                    stream.flush()?;
                }
            }
            EmailReceivingState::WaitingForData => {
                if command.contains("data") {
                    self.state = EmailReceivingState::ReceivingData;
                    stream.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")?;
                    stream.flush()?;
                }
            }
            EmailReceivingState::ReceivingData => {
                self.email.raw_data.push_str(&command);

                if command.contains("\r\n.\r\n") {
                    // Handle end of email data
                    self.state = EmailReceivingState::WaitingForQuit;
                    stream.write_all(b"250 OK\r\n")?;
                    stream.flush()?;
                }
            }
            EmailReceivingState::WaitingForQuit => {
                if command.contains("quit") {
                    stream.write_all(b"221 Bye\r\n")?;
                    stream.flush()?;
                }
            }
        }
        Ok(())
    }

    fn parse_body(&mut self) {
        let parts: Vec<String> = self.email.raw_data.split("\r\n\r\n").map(|s| s.to_string()).collect();
        if parts.len() >= 2 {
            for header in parts[0].lines() {
                if let Some((key, value)) = header.split_once(":") {
                    self.email.headers.insert(key.trim().to_string(), value.trim().to_string());
                }
            }
            self.email.content = parts[1..].join("\r\n\r\n");
        } else {
            self.email.content = self.email.raw_data.clone();
        }

        let mut new_headers = HashMap::new();
        for (key, value) in &self.email.headers {
            let mut new_key: String = key.to_string();
            let mut new_value: String = value.to_string();
            new_key = new_key.to_lowercase().replace("\r", "").replace("\n", "");
            new_value = new_value.replace("\r", "").replace("\n", "");
            new_headers.insert(new_key, new_value);
        }
        self.email.headers = new_headers;
    }

    fn get_email(&self) -> Email {
        self.email.clone()
    }

}