use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;

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
