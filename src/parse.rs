use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsExtension};

use crate::model::Attribution;

pub fn handle_dns_packet(payload: &[u8], attribution: &Attribution) {
    let Ok(msg) = Message::from_vec(payload) else {
        return;
    };

    for answer in msg.answers {
        if matches!(answer.record_type(), RecordType::A | RecordType::AAAA) {
            if let Some(ip) = answer.data.ip_addr() {
                let hostname = answer.name.to_string().trim_end_matches('.').to_string();
                attribution.record_dns(ip, hostname);
            }
        }
    }
}

pub fn extract_sni(tcp_payload: &[u8]) -> Option<String> {
    let (_, record) = parse_tls_plaintext(tcp_payload).ok()?;

    for msg in record.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
            let ext_bytes = ch.ext?;
            let (_, extensions) = tls_parser::parse_tls_extensions(ext_bytes).ok()?;
            for ext in extensions {
                if let TlsExtension::SNI(sni_list) = ext {
                    if let Some((_, hostname)) = sni_list.first() {
                        return Some(String::from_utf8_lossy(hostname).to_string());
                    }
                }
            }
        }
    }
    None
}
