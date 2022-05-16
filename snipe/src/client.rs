use std::{
    io::{Read, Write},
    sync::atomic::AtomicI32,
    time::Instant,
};

use rasn::types::{ObjectIdentifier, OctetString};
use rasn_smi::v2::ObjectSyntax;
use rasn_snmp::{
    v2::VarBindList,
    v3::{HeaderData, Message, ScopedPdu, ScopedPduData, USMSecurityParameters},
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::rfc3412::MessageFlags;

const SNMP_VERSION: i32 = 3;
const MAX_MESSAGE_SIZE: i32 = 65507;

pub struct DefaultSnmpInterface<T: AsyncRead + AsyncWrite> {
    stream: T,
    usm: USMSecurityParameters,
    msg_id: i32,
    flags: MessageFlags,
}

impl<T: AsyncRead + AsyncWrite> DefaultSnmpInterface<T> {
    pub fn encrypt_pdu(&mut self, pdu: ScopedPdu) -> ScopedPduData {

    }
    pub fn create_msg(&mut self, pdu: ScopedPdu) -> Result<Message, crate::Error> {
        Ok(Message {
            version: SNMP_VERSION.into(),
            global_data: HeaderData {
                message_id: {
                    self.msg_id += 1;
                    if self.msg_id == i32::MAX {
                        self.msg_id = 0; // bad!
                    }
                    self.msg_id.into()
                },
                max_size: MAX_MESSAGE_SIZE.into(),
                flags: self.flags.try_into()?,
                security_model: (),
            },
            security_parameters: (),
            scoped_data: ScopedPduData::CleartextPdu(pdu),
        })
    }
    pub fn format_read(oid: ObjectIdentifier) -> Message {
        todo!()
    }
    pub fn format_write(oid: ObjectIdentifier) -> Message {
        todo!()
    }
}

#[async_trait::async_trait]
impl<T: AsyncRead + AsyncWrite + Send + Sync> crate::SnmpInterface for DefaultSnmpInterface<T> {
    async fn read(&mut self, oid: ObjectIdentifier) -> Result<ObjectSyntax, crate::Error> {
        todo!()
    }
    async fn write(
        &mut self,
        oid: ObjectIdentifier,
        value: rasn_smi::v2::ObjectSyntax,
    ) -> Result<(), crate::Error> {
        todo!()
    }
    async fn bulk(&mut self, oid: ObjectIdentifier) -> Result<VarBindList, crate::Error> {
        todo!()
    }
}
