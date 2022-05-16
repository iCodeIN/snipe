use rasn::types::OctetString;

// msgFlags   OCTET STRING (SIZE(1)),
//            --  .... ...1   authFlag
//            --  .... ..1.   privFlag
//            --  .... .1..   reportableFlag
//            --              Please observe:
//            --  .... ..00   is OK, means noAuthNoPriv
//            --  .... ..01   is OK, means authNoPriv
//            --  .... ..10   reserved, MUST NOT be used.
//            --  .... ..11   is OK, means authPriv

#[derive(Default)]
pub struct MessageFlags {
    pub reportable: bool,
    pub auth: bool,
    pub privacy: bool,
}

impl TryFrom<MessageFlags> for OctetString {
    type Error = crate::Error;

    fn try_from(value: MessageFlags) -> Result<Self, Self::Error> {
        if value.privacy && !value.auth {
            Err(crate::Error::PrivNoAuth)
        } else {
            let mut ret = 0_u8;
            if value.reportable {
                ret |= 0x100_u8;
            }

            if value.privacy {
                ret |= 0x010_u8;
            }

            if value.auth {
                ret |= 0x001_u8;
            }

            Ok(vec![ret].into())
        }
    }
}
