extern crate tokio;

use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use rand::random;
use regex::Regex;
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Write};
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, fs};
use std::error::Error;
use anyhow::{ensure, Context};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;
use tokio::time;

pub struct Controller {
    host: String,
    port: u16,
    tor_password: String,
    desc_event_tx: UnboundedSender<Message>,
    desc_content_event_tx: UnboundedSender<Message>,
    status_event_tx: UnboundedSender<Message>,
    re_connect_tx: Sender<()>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    msgs_rx: Arc<Mutex<UnboundedReceiver<Message>>>,
}

// https://github.com/torproject/torspec/blob/8961bb4d83fccb2b987f9899ca83aa430f84ab0c/control-spec.txt#L248
#[derive(PartialEq)]
enum LineType {
    MidReplyLine,
    DataReplyLine,
    EndReplyLine,
}

pub struct Message(String);

impl Message {
    // Replies: https://github.com/torproject/torspec/blob/8961bb4d83fccb2b987f9899ca83aa430f84ab0c/control-spec.txt#L2121
    pub fn raw(&self) -> String { self.0.to_owned() }
    pub fn code(&self) -> usize { self.0[0..3].parse().expect("a number") }
    pub fn is_ok(&self) -> bool {
        let code = self.code();
        matches!(code, 200..=299)
    }
    fn is_async(&self) -> bool { self.0.starts_with("6") }
    fn is_data(&self) -> bool { &self.0[3..4] == "+" }
    pub fn keywords(&self) -> String {
        let end_idx = self.0.find("\r\n").expect("end pattern not found");
        self.0[4..end_idx].to_owned()
    }
    pub fn inner(&self) -> String {
        let start_idx = if self.is_data() { self.0.find("\r\n").expect("start pattern not found") + 2 } else { 4 };
        let end_pattern = if self.is_data() { "\r\n.\r\n" } else { "\r\n" };
        let end_idx = self.0.find(end_pattern).expect("end pattern not found");
        self.0[start_idx..end_idx].to_owned()
    }
}

// Read the raw message coming from tor control, and return it.
async fn read_msg<R>(buf_reader: &mut BufReader<R>) -> anyhow::Result<Message>
where
    R: AsyncRead + Unpin
{
    let mut buf = String::new();
    buf_reader.read_line(&mut buf).await?;
    ensure!(buf.len() > 4, "invalid buffer length");
    let code = String::from(&buf[..3]);
    let line_type = match &buf[3..4] {
        " " => LineType::EndReplyLine,
        "+" => LineType::DataReplyLine,
        "-" => LineType::MidReplyLine,
        _ => panic!("invalid line type"),
    };
    if line_type == LineType::EndReplyLine { // "250 OK\r\n" "650 HS_DESC ...\r\n"
        return Ok(Message(buf));
    }
    loop {
        let mut new_line_buf = String::new();
        buf_reader.read_line(&mut new_line_buf).await?;
        buf.write_str(&new_line_buf)?;
        if new_line_buf.starts_with(format!("{code} OK").as_str()) {
            break;
        }
    }
    Ok(Message(buf))
}

enum ProtocolInfoMethods {
    Auth,
    Cookie(Vec<u8>),
    Hashed,
}

async fn protocol_info(w: &mut OwnedWriteHalf, msgs_rx: &mut UnboundedReceiver<Message>) -> anyhow::Result<ProtocolInfoMethods> {
    w.write("PROTOCOLINFO\n".as_bytes()).await.map_err(|_| ControllerErr::SocketClosedErr)?;
    let msg = msgs_rx.recv().await.ok_or(ControllerErr::SocketClosedErr)?.raw();
    let mut lines = msg.lines();
    let second = lines.nth(1).context("lines nth 1 failed")?;
    if second.contains("NULL") {
        return Ok(ProtocolInfoMethods::Auth);
    } else if second.contains("HASHEDPASSWORD") {
        return Ok(ProtocolInfoMethods::Hashed);
    } else if second.contains("COOKIE") {
        let captures = Regex::new(r#"250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="([^"]+)""#)?.captures(second).context("captures failed")?;
        let cookie_path = &captures[1];
        let cookie_content = fs::read(cookie_path)?;
        return Ok(ProtocolInfoMethods::Cookie(cookie_content));
    }
    Ok(ProtocolInfoMethods::Auth)
}

async fn auth(w: &mut OwnedWriteHalf, msgs_rx: &mut UnboundedReceiver<Message>, tor_password: &str) -> anyhow::Result<()> {
    w.write(format!("AUTHENTICATE \"{tor_password}\"\n").as_bytes()).await.map_err(|_| ControllerErr::SocketClosedErr)?;
    let msg = msgs_rx.recv().await.ok_or(ControllerErr::SocketClosedErr)?;
    ensure!(msg.code() == 250, "{}", msg.raw());
    Ok(())
}

async fn auth_with_cookie(w: &mut OwnedWriteHalf, msgs_rx: &mut UnboundedReceiver<Message>, cookie_content: &[u8]) -> anyhow::Result<()> {
    let client_nonce = hex::encode(random::<[u8; 32]>()).to_uppercase();
    w.write(format!("AUTHCHALLENGE SAFECOOKIE {client_nonce}\n").as_bytes()).await.map_err(|_| ControllerErr::SocketClosedErr)?;
    let msg = msgs_rx.recv().await.ok_or(ControllerErr::SocketClosedErr)?.raw();
    let captures = Regex::new(r#"SERVERNONCE=(\S+)"#)?.captures(&msg).context("captures failed")?;
    let server_nonce = &captures[1];
    let cookie_str = hex::encode(cookie_content).to_uppercase();
    let to_hash = format!("{cookie_str}{client_nonce}{server_nonce}");
    let to_hash_bytes = hex::decode(to_hash)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(b"Tor safe cookie authentication controller-to-server hash")?;
    mac.update(to_hash_bytes.as_slice());
    let hashed = mac.finalize();
    let sha = hex::encode(hashed.into_bytes()).to_uppercase();
    w.write(format!("AUTHENTICATE {sha}\n").as_bytes()).await.map_err(|_| ControllerErr::SocketClosedErr)?;
    let msg = msgs_rx.recv().await.ok_or(ControllerErr::SocketClosedErr)?.raw();
    ensure!(msg.eq("250 OK\r\n"), "invalid response code");
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ConnectionErr {
    host: String,
    port: u16,
}

impl Display for ConnectionErr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Unable to connect to Tor control port: {}:{}", self.host, self.port)
    }
}

impl Error for ConnectionErr {}

#[derive(Debug)]
pub enum ControllerErr {
    SocketClosedErr,
    AuthErr,
}

impl Display for ControllerErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ControllerErr {}

async fn connect(
    host: &str,
    port: u16,
    desc_event_tx: UnboundedSender<Message>,
    desc_content_event_tx: UnboundedSender<Message>,
    status_event_tx: UnboundedSender<Message>,
    re_connect_tx: Sender<()>,
) -> anyhow::Result<(OwnedWriteHalf, UnboundedReceiver<Message>)> {
    let (msgs_tx, msgs_rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let conn = TcpStream::connect(format!("{host}:{port}")).await.map_err(|_| ConnectionErr { host: host.to_owned(), port })?;
    let (reader, writer) = conn.into_split();
    tokio::spawn(read_socket(reader, msgs_tx, desc_event_tx, desc_content_event_tx, status_event_tx, re_connect_tx));
    Ok((writer, msgs_rx))
}

async fn socket_auth(writer: &mut OwnedWriteHalf, msgs_rx: &mut UnboundedReceiver<Message>, password: &str) -> anyhow::Result<()> {
    let protocol_info = protocol_info(writer, msgs_rx).await?;
    match protocol_info {
        ProtocolInfoMethods::Auth | ProtocolInfoMethods::Hashed => auth(writer, msgs_rx, password).await?,
        ProtocolInfoMethods::Cookie(cookie_content) => auth_with_cookie(writer, msgs_rx, &cookie_content).await?,
    }
    Ok(())
}

async fn read_socket(
    reader: OwnedReadHalf,
    msgs_tx: UnboundedSender<Message>,
    desc_event_tx: UnboundedSender<Message>,
    desc_content_event_tx: UnboundedSender<Message>,
    status_event_tx: UnboundedSender<Message>,
    re_connect_tx: Sender<()>,
) {
    let mut buf_reader = BufReader::new(reader);
    while read_socket_msg(&mut buf_reader, &msgs_tx, &desc_event_tx, &desc_content_event_tx, &status_event_tx).await.is_ok() {}
    error!("Tor control connection lost");
    re_connect_tx.send(()).await.expect("receiver to not be closed")
}

async fn read_socket_msg(
    buf_reader: &mut BufReader<OwnedReadHalf>,
    msgs_tx: &UnboundedSender<Message>,
    desc_event_tx: &UnboundedSender<Message>,
    desc_content_event_tx: &UnboundedSender<Message>,
    status_event_tx: &UnboundedSender<Message>,
) -> anyhow::Result<()> {
    let msg = read_msg(buf_reader).await?;
    if msg.is_async() {
        let keywords = msg.keywords();
        let event_type = keywords.split_once(" ");
        match event_type {
            Some(("HS_DESC", _))         => desc_event_tx.send(msg)?,
            Some(("HS_DESC_CONTENT", _)) => desc_content_event_tx.send(msg)?,
            Some(("STATUS_CLIENT", _))   => status_event_tx.send(msg)?,
            _ => {},
        }
        return Ok(());
    }
    msgs_tx.send(msg)?;
    Ok(())
}

impl Controller {
    pub async fn new(
        host: &str,
        port: u16,
        tor_password: &str,
        desc_event_tx: UnboundedSender<Message>,
        desc_content_event_tx: UnboundedSender<Message>,
        status_event_tx: UnboundedSender<Message>,
        re_connect_tx: Sender<()>,
    ) -> anyhow::Result<Self> {
        let (mut writer, mut msgs_rx) = connect(
            host, port, desc_event_tx.clone(), desc_content_event_tx.clone(), status_event_tx.clone(), re_connect_tx.clone(),
        ).await?;
        socket_auth(&mut writer, &mut msgs_rx, tor_password).await?;

        let writer = Arc::new(Mutex::new(writer));
        let msgs_rx = Arc::new(Mutex::new(msgs_rx));

        debug!("Successfully authenticated on the Tor control connection.");
        Ok(Self {
            writer,
            msgs_rx,
            host: host.to_owned(),
            port,
            tor_password: tor_password.to_owned(),
            desc_event_tx,
            desc_content_event_tx,
            status_event_tx,
            re_connect_tx,
        })
    }

    pub async fn re_connect(&mut self) {
        time::sleep(Duration::from_secs(2)).await;
        while self.do_re_connect().await.is_err() {
            error!("Failed to re-connect controller.");
            time::sleep(Duration::from_secs(10)).await;
        }
        info!("Tor control re-connected");
        time::sleep(Duration::from_secs(5)).await;
    }

    async fn do_re_connect(&mut self) -> anyhow::Result<()> {
        let (mut writer, mut msgs_rx) = connect(
            &self.host,
            self.port,
            self.desc_event_tx.clone(),
            self.desc_content_event_tx.clone(),
            self.status_event_tx.clone(),
            self.re_connect_tx.clone(),
        ).await?;
        socket_auth(&mut writer, &mut msgs_rx, &self.tor_password).await?;
        self.writer = Arc::new(Mutex::new(writer));
        self.msgs_rx = Arc::new(Mutex::new(msgs_rx));
        self.set_events().await?;
        Ok(())
    }

    pub async fn msg(&mut self, msg: &[u8]) -> Result<Message, ControllerErr> {
        self.writer.lock().await.write(msg).await.map_err(|_| ControllerErr::SocketClosedErr)?;
        Ok(self.msgs_rx.lock().await.recv().await.ok_or(ControllerErr::SocketClosedErr)?)
    }

    pub async fn get_md_consensus(&mut self) -> anyhow::Result<String> {
        let consensus = self.get_info("dir/status-vote/current/consensus-microdesc").await?;
        let consensus = consensus
            .strip_prefix("250+dir/status-vote/current/consensus-microdesc=\r\n").context("missing prefix")?
            .strip_suffix(".\r\n250 OK\r\n").context("missing suffix")?;
        Ok(consensus.to_owned())
    }

    pub async fn get_version(&mut self) -> Result<String, ControllerErr> {
        let msg = self.get_info("version").await?;
        Ok(msg.trim_start_matches("250-version=").trim_end_matches("\r\n250 OK\r\n").to_owned())
    }

    pub async fn set_events(&mut self) -> Result<(), ControllerErr> {
        self.msg(b"SETEVENTS SIGNAL CONF_CHANGED STATUS_SERVER STATUS_CLIENT HS_DESC HS_DESC_CONTENT\n").await?;
        Ok(())
    }

    pub async fn signal(&mut self, signal: &str) -> Result<String, ControllerErr> {
        Ok(self.msg(format!("SIGNAL {signal}\n").as_bytes()).await?.raw())
    }

    pub async fn mark_tor_as_active(&mut self) {
        if let Err(ControllerErr::SocketClosedErr) = self.signal("ACTIVE").await {
            warn!("Can't connect to the control port to send ACTIVE signal. Moving on...");
        }
    }

    async fn hs_fetch(&mut self, addr: &str) -> Result<String, ControllerErr> {
        Ok(self.msg(format!("HSFETCH {addr}\n").as_bytes()).await?.raw())
    }

    async fn get_info(&mut self, s: &str) -> Result<String, ControllerErr> {
        Ok(self.msg(format!("GETINFO {s}\n").as_bytes()).await?.raw())
    }

    pub async fn get_hidden_service_descriptor(&mut self, address: &str, _await_result: bool) -> Result<(), ControllerErr> {
        self.hs_fetch(address).await?;
        Ok(())
    }

    pub async fn get_microdescriptors(&mut self) -> anyhow::Result<Vec<MicroDescriptor>> {
        let md_all = self.get_info("md/all").await?;
        let md_all = md_all
            .strip_prefix("250+md/all=\r\n").context("missing prefix")?
            .strip_suffix(".\r\n250 OK\r\n").context("missing suffix")?;
        Ok(extract_microdescriptors(md_all))
    }
}

fn extract_microdescriptors(s: &str) -> Vec<MicroDescriptor> {
    // tor_netdoc::doc::microdesc::Microdesc::parse is ~50 times slower than the following code
    // 124ms (our code)  VS  5.88seconds (Microdesc::parse)
    let sep = "onion-key\r\n";
    s.split(sep).skip(1).map(|part| {
        let mut md = MicroDescriptor::new(format!("{sep}{part}"));
        for line in part.split("\r\n") {
            if let Some(line) = line.strip_prefix("id ed25519 ") {
                md.identifiers.insert("ed25519".to_owned(), line.to_owned());
            }
        }
        md
    }).collect()
}

#[derive(Clone)]
pub struct MicroDescriptor {
    pub identifiers: HashMap<String, String>,
    raw: String,
}

impl MicroDescriptor {
    fn new(raw: String) -> Self {
        let identifiers = HashMap::new();
        Self { raw, identifiers }
    }

    pub fn digest(&self) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.raw.replace("\r",""));
        let src = hasher.finalize();
        general_purpose::STANDARD.encode(src).trim_end_matches("=").to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use tokio::io::BufReader;
    use crate::onionbalance::controller::{extract_microdescriptors, read_msg, Message};

    #[tokio::test]
    async fn test_read_msg() {
        let txt = "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250-VERSION Tor=\"0.4.8.7\"\r\n250 OK\r\n";
        let cursor = Cursor::new(txt);
        let mut buf_reader = BufReader::new(cursor);
        let msg = read_msg(&mut buf_reader).await.unwrap();
        assert_eq!(msg.raw(), txt);
    }

    #[tokio::test]
    async fn test_extract_microdescriptors() {
        let txt = "onion-key\r\ndata1\r\nonion-key\r\ndata2\r\nid ed25519 test\r\n";
        let out = extract_microdescriptors(txt);
        assert_eq!(2, out.len());
        assert_eq!("onion-key\r\ndata1\r\n", out[0].raw);
        assert_eq!("onion-key\r\ndata2\r\nid ed25519 test\r\n", out[1].raw);
        assert_eq!("test", out[1].identifiers.get("ed25519").unwrap());
    }

    #[test]
    fn test_message_keywords() {
        let msg = Message("250 some keywords\r\n".to_string());
        let expected = "some keywords";
        assert_eq!(expected, msg.keywords());
    }
}