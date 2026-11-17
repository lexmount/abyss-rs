//! Target DNS over TCP inside the encrypted tunnel, never the host resolver.

use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use futures_util::{StreamExt as _, stream::FuturesUnordered};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{config::Settings, tunnel::Tunnel};

/// Races permitted address families through both DNS and TCP establishment.
pub(super) struct TargetResolver<'a> {
    settings: &'a Settings,
    tunnel: &'a Tunnel,
}

impl<'a> TargetResolver<'a> {
    pub(super) const fn new(settings: &'a Settings, tunnel: &'a Tunnel) -> Self {
        Self { settings, tunnel }
    }

    pub(super) async fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<tokio_smoltcp::TcpStream> {
        if self.settings.dns_servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "WireGuard target DNS requires dns_servers",
            ));
        }
        let mut name = Name::from_ascii(host).map_err(|_| invalid())?;
        // DNS wire names are always absolute, even when the authority omits its dot.
        name.set_fqdn(true);
        let mut requests = self
            .settings
            .dns_servers
            .iter()
            .flat_map(|server| {
                let name = &name;
                self.settings.addresses.iter().map(move |local| {
                    let kind = if local.is_ipv4() {
                        RecordType::A
                    } else {
                        RecordType::AAAA
                    };
                    self.connect_query(*server, name.clone(), kind, port)
                })
            })
            .collect::<FuturesUnordered<_>>();
        let mut error = no_addresses();
        while let Some(result) = requests.next().await {
            match result {
                Ok(stream) => return Ok(stream),
                Err(cause) => error = cause,
            }
        }
        Err(error)
    }

    async fn connect_query(
        &self,
        server: IpAddr,
        name: Name,
        kind: RecordType,
        port: u16,
    ) -> io::Result<tokio_smoltcp::TcpStream> {
        let mut attempts = self
            .query(server, name, kind)
            .await?
            .into_iter()
            .filter(|ip| self.settings.allows(ip))
            .map(|ip| self.tunnel.connect(SocketAddr::new(ip, port)))
            .collect::<FuturesUnordered<_>>();
        let mut error = no_addresses();
        while let Some(result) = attempts.next().await {
            match result {
                Ok(stream) => return Ok(stream),
                Err(cause) => error = cause,
            }
        }
        Err(error)
    }

    async fn query(
        &self,
        server: IpAddr,
        name: Name,
        kind: RecordType,
    ) -> io::Result<Box<[IpAddr]>> {
        let random = uuid::Uuid::new_v4();
        let id = u16::from_ne_bytes(random.as_bytes()[..2].try_into().expect("UUID prefix"));
        let mut request = Message::new();
        request
            .set_id(id)
            .set_recursion_desired(true)
            .add_query(Query::query(name, kind));
        let bytes = request.to_vec().map_err(|_| invalid())?;
        let length = u16::try_from(bytes.len()).map_err(|_| invalid())?;
        let mut stream = self.tunnel.connect(SocketAddr::new(server, 53)).await?;
        stream.write_u16(length).await?;
        stream.write_all(&bytes).await?;
        let length = usize::from(stream.read_u16().await?);
        let mut reply = vec![0; length].into_boxed_slice();
        stream.read_exact(&mut reply).await?;
        let response = Message::from_vec(&reply).map_err(|_| invalid())?;
        // The request retains its one question through validation; no name clone
        // is needed just to remember what was sent on the wire.
        Ok(DnsResponse::new(&response, id, &request.queries()[0])?.addresses())
    }
}

/// Only validated replies expose address extraction; records remain borrowed.
struct DnsResponse<'a> {
    message: &'a Message,
    question: &'a Query,
}

impl<'a> DnsResponse<'a> {
    fn new(message: &'a Message, id: u16, question: &'a Query) -> io::Result<Self> {
        if message.id() != id
            || message.message_type() != MessageType::Response
            || message.op_code() != OpCode::Query
            || message.truncated()
            || message.queries() != std::slice::from_ref(question)
        {
            return Err(invalid());
        }
        if message.response_code() != ResponseCode::NoError {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "WireGuard DNS query failed",
            ));
        }
        Ok(Self { message, question })
    }

    fn addresses(&self) -> Box<[IpAddr]> {
        let mut names = vec![self.question.name()];
        // Answers may precede their CNAME sources. Keep the bounded fixed-point
        // walk, borrowing records so unordered chains need no cloned names.
        for _ in 0_u8..16 {
            let previous_count = names.len();
            self.message.answers().iter().for_each(|record| {
                if names.contains(&record.name())
                    && let RData::CNAME(alias) = record.data()
                {
                    let alias = &alias.0;
                    if !names.contains(&alias) {
                        names.push(alias);
                    }
                }
            });
            if names.len() == previous_count {
                break;
            }
        }
        self.message
            .answers()
            .iter()
            .filter(|record| names.contains(&record.name()))
            .filter_map(|record| match record.data() {
                RData::A(ip) if self.question.query_type() == RecordType::A => {
                    Some(IpAddr::V4(ip.0))
                }
                RData::AAAA(ip) if self.question.query_type() == RecordType::AAAA => {
                    Some(IpAddr::V6(ip.0))
                }
                _ => None,
            })
            .collect()
    }
}

fn no_addresses() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "WireGuard DNS returned no permitted target addresses",
    )
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid WireGuard DNS response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{
        Record,
        rdata::{A, AAAA, CNAME},
    };

    #[test]
    fn validates_wire_question_and_follows_only_its_cname_chain() {
        let name = Name::from_ascii("plain.invalid.").unwrap();
        let alias = Name::from_ascii("alias.invalid.").unwrap();
        let question = Query::query(name.clone(), RecordType::A);
        let mut reply = Message::new();
        reply
            .set_id(123)
            .set_message_type(MessageType::Response)
            .add_query(question.clone());
        reply.add_answer(Record::from_rdata(
            name,
            60,
            RData::CNAME(CNAME(alias.clone())),
        ));
        reply.add_answer(Record::from_rdata(
            alias,
            60,
            RData::A(A("10.77.0.1".parse().unwrap())),
        ));
        reply.add_answer(Record::from_rdata(
            Name::from_ascii("unrelated.invalid.").unwrap(),
            60,
            RData::A(A("10.77.0.99".parse().unwrap())),
        ));
        let mut decoded = Message::from_vec(&reply.to_vec().unwrap()).unwrap();
        assert_eq!(
            DnsResponse::new(&decoded, 123, &question)
                .unwrap()
                .addresses()
                .as_ref(),
            &["10.77.0.1".parse::<IpAddr>().unwrap()]
        );
        assert!(
            DnsResponse::new(&decoded, 124, &question).is_err(),
            "transaction ID must match"
        );
        decoded.set_truncated(true);
        assert!(
            DnsResponse::new(&decoded, 123, &question).is_err(),
            "truncated TCP replies are rejected"
        );
        decoded
            .set_truncated(false)
            .set_response_code(ResponseCode::NXDomain);
        assert!(
            DnsResponse::new(&decoded, 123, &question).is_err(),
            "NXDOMAIN must not supply target addresses"
        );
    }

    #[test]
    fn follows_unordered_cnames_and_stops_cycles_without_mixing_address_families() {
        let name = Name::from_ascii("plain.invalid.").unwrap();
        let middle = Name::from_ascii("middle.invalid.").unwrap();
        let target = Name::from_ascii("target.invalid.").unwrap();
        let question = Query::query(name.clone(), RecordType::A);
        let mut reply = Message::new();
        reply
            .set_id(123)
            .set_message_type(MessageType::Response)
            .add_query(question.clone())
            .add_answer(Record::from_rdata(
                middle.clone(),
                60,
                RData::CNAME(CNAME(target.clone())),
            ))
            .add_answer(Record::from_rdata(
                target.clone(),
                60,
                RData::CNAME(CNAME(name.clone())),
            ))
            .add_answer(Record::from_rdata(
                target.clone(),
                60,
                RData::AAAA(AAAA("fd77::1".parse().unwrap())),
            ))
            .add_answer(Record::from_rdata(
                target,
                60,
                RData::A(A("10.77.0.1".parse().unwrap())),
            ))
            .add_answer(Record::from_rdata(
                Name::from_ascii("unrelated.invalid.").unwrap(),
                60,
                RData::A(A("10.77.0.99".parse().unwrap())),
            ))
            .add_answer(Record::from_rdata(name, 60, RData::CNAME(CNAME(middle))));
        let decoded = Message::from_vec(&reply.to_vec().unwrap()).unwrap();
        assert_eq!(
            DnsResponse::new(&decoded, 123, &question)
                .unwrap()
                .addresses()
                .as_ref(),
            &["10.77.0.1".parse::<IpAddr>().unwrap()]
        );
        let wrong_question = Query::query(question.name().clone(), RecordType::AAAA);
        assert!(
            DnsResponse::new(&decoded, 123, &wrong_question).is_err(),
            "the reply must match the requested address family"
        );
    }
}
