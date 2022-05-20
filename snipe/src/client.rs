use std::{
    io::{Read, Write},
    sync::atomic::AtomicI32,
    time::{Instant, SystemTime},
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

// TODO REPLACE THIS! THIS IS FROM SNMPBULKWALK!
const ENGINE_ID: &[u8] = &[
    0x6e, 0x69, 0x67, 0x68, 0x74, 0x72, 0x61, 0x76, 0x65, 0x6e, 0x3c, 0xcf, 0x03, 0x40,
];

pub struct DefaultSnmpInterface<T: AsyncRead + AsyncWrite> {
    stream: T,
    engine_id: OctetString,
    msg_id: i32,
    boots: i32,
    init_time: Instant,
    user_name: OctetString,
    flags: MessageFlags,
}

impl<T: AsyncRead + AsyncWrite> DefaultSnmpInterface<T> {
    fn reinit(&mut self) {
        self.msg_id = 0;
        self.init_time = Instant::now();
        self.boots += 1;
    }

    fn time(&mut self) -> i32 {
        let time = Instant::now().duration_since(self.init_time).as_secs();
        if time > i32::MAX as u64 {
            self.reinit();
            self.time()
        } else {
            time as i32
        }
    }

    pub fn encrypt_pdu(&mut self, pdu: ScopedPdu) -> ScopedPduData {
        todo!()
    }
    pub fn create_msg(&mut self, pdu: ScopedPdu) -> Result<Message, crate::Error> {
        Ok(Message {
            version: SNMP_VERSION.into(),
            global_data: HeaderData {
                message_id: {
                    self.msg_id += 1;
                    if self.msg_id == i32::MAX {
                        self.reinit();
                    }
                    self.msg_id.into()
                },
                max_size: MAX_MESSAGE_SIZE.into(),
                flags: self.flags.try_into()?,
                security_model: 3_u32.into(),
            },
            security_parameters: USMSecurityParameters {
                authoritative_engine_id: self.engine_id,
                authoritative_engine_time: self.time().into(),
                // NOTE: ORDER MATTERS HERE!
                authoritative_engine_boots: self.boots.into(),
                user_name: self.user_name,
                authentication_parameters: todo!(),
                privacy_parameters: todo!(),
            },
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
