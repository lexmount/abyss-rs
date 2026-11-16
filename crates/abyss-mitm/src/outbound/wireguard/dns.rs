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

pub(super) async fn connect(
    host: &str,
    port: u16,
    settings: &Settings,
    tunnel: &Tunnel,
) -> io::Result<tokio_smoltcp::TcpStream> {
    if settings.dns_servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "WireGuard target DNS requires dns_servers",
        ));
    }
    let mut name = Name::from_ascii(host).map_err(|_| invalid())?;
    // DNS wire names are always absolute, even when the authority omits its dot.
    name.set_fqdn(true);
    let mut requests = FuturesUnordered::new();
    for server in &settings.dns_servers {
        for local in &settings.addresses {
            let kind = if local.is_ipv4() {
                RecordType::A
            } else {
                RecordType::AAAA
            };
            let name = name.clone();
            requests.push(async move {
                let addresses = query(*server, name, kind, tunnel).await?;
                let mut attempts = addresses
                    .into_iter()
                    .filter(|ip| settings.allows(*ip))
                    .map(|ip| tunnel.connect(SocketAddr::new(ip, port)))
                    .collect::<FuturesUnordered<_>>();
                let mut error = io::Error::new(
                    io::ErrorKind::NotFound,
                    "WireGuard DNS returned no permitted target addresses",
                );
                while let Some(result) = attempts.next().await {
                    match result {
                        Ok(stream) => return Ok(stream),
                        Err(cause) => error = cause,
                    }
                }
                Err(error)
            });
        }
    }
    let mut error = io::Error::new(
        io::ErrorKind::NotFound,
        "WireGuard DNS returned no permitted target addresses",
    );
    while let Some(result) = requests.next().await {
        match result {
            Ok(stream) => return Ok(stream),
            Err(cause) => error = cause,
        }
    }
    Err(error)
}

async fn query(
    server: IpAddr,
    name: Name,
    kind: RecordType,
    tunnel: &Tunnel,
) -> io::Result<Vec<IpAddr>> {
    let random = uuid::Uuid::new_v4();
    let id = u16::from_ne_bytes(random.as_bytes()[..2].try_into().expect("UUID prefix"));
    let question = Query::query(name, kind);
    let mut request = Message::new();
    request
        .set_id(id)
        .set_recursion_desired(true)
        .add_query(question.clone());
    let bytes = request.to_vec().map_err(|_| invalid())?;
    let length = u16::try_from(bytes.len()).map_err(|_| invalid())?;
    let mut stream = tunnel.connect(SocketAddr::new(server, 53)).await?;
    stream.write_u16(length).await?;
    stream.write_all(&bytes).await?;
    let length = usize::from(stream.read_u16().await?);
    let mut reply = vec![0; length];
    stream.read_exact(&mut reply).await?;
    let response = Message::from_vec(&reply).map_err(|_| invalid())?;
    parse(&response, id, &question)
}

fn parse(response: &Message, id: u16, question: &Query) -> io::Result<Vec<IpAddr>> {
    if response.id() != id
        || response.message_type() != MessageType::Response
        || response.op_code() != OpCode::Query
        || response.truncated()
        || response.queries() != [question.clone()]
    {
        return Err(invalid());
    }
    if response.response_code() != ResponseCode::NoError {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "WireGuard DNS query failed",
        ));
    }
    let mut names = vec![question.name().clone()];
    for _ in 0_u8..16 {
        let mut added = false;
        for record in response.answers() {
            if names.contains(record.name())
                && let RData::CNAME(alias) = record.data()
                && !names.contains(&alias.0)
            {
                names.push(alias.0.clone());
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    Ok(response
        .answers()
        .iter()
        .filter(|record| names.contains(record.name()))
        .filter_map(|record| match record.data() {
            RData::A(ip) if question.query_type() == RecordType::A => Some(IpAddr::V4(ip.0)),
            RData::AAAA(ip) if question.query_type() == RecordType::AAAA => Some(IpAddr::V6(ip.0)),
            _ => None,
        })
        .collect())
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid WireGuard DNS response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{
        Record,
        rdata::{A, CNAME},
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
            parse(&decoded, 123, &question).unwrap(),
            vec!["10.77.0.1".parse::<IpAddr>().unwrap()]
        );
        assert!(
            parse(&decoded, 124, &question).is_err(),
            "transaction ID must match"
        );
        decoded.set_truncated(true);
        assert!(
            parse(&decoded, 123, &question).is_err(),
            "truncated TCP replies are rejected"
        );
        decoded
            .set_truncated(false)
            .set_response_code(ResponseCode::NXDomain);
        assert!(
            parse(&decoded, 123, &question).is_err(),
            "NXDOMAIN must not supply target addresses"
        );
    }
}
