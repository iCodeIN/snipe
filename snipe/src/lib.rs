use std::ops::Deref;

pub use rasn::prelude::*;
pub use rasn as asn;
pub use rasn_snmp as snmp;
use snmp::v2::{ObjectSyntax, VarBindList};

extern crate self as snipe;

pub use snipe_macros::*;

// Design:
// snmp_interface.my_mib_name()
//     where my_mib_name is implemented by trait GetMyMibName generated from a MIB (method/trait name is customizable)
//     this trait is implemented on anything that implements GetSnmpInterface
//     this method returns MyMibName (struct name is customizable)
// .ip_address()
//     where ip_address is implemented by trait GetIpAddressOid generated from an OID called ipAddress
//     this trait is implemented on MyMibName
//     this method returns IpAddress
// .get().unwrap()
//     where get is default-implemented by trait ReadableScalar
//         where ReadableScalar requires trait Scalar
//             Scalar has an OID constant
//             Scalar has an associated type
//         where ReadableScalar requires trait GetSnmpInterface
//         default implementation uses GetSnmpInterface and does a read of the OID indicated by the Scalar implementation
//     this trait is implemented on IpAddress
//     this method returns Result<{Scalar's associated type}, Error>

// ------------------------------------- FIXED ------------------------------------- 

trait SnmpInterface {
    fn read(&mut self, oid: ObjectIdentifier) -> Result<ObjectSyntax, Error>;
    fn write(&mut self, oid: ObjectIdentifier, value: ObjectSyntax) -> Result<(), Error>;
    fn bulk(&mut self, oid: ObjectIdentifier) -> Result<VarBindList, Error>;
}

trait GetSnmpInterface {
    type Interface: SnmpInterface;
    fn snmp_interface(&mut self) -> &mut Self::Interface;
}

impl<T: SnmpInterface> GetSnmpInterface for T {
    type Interface = T;

    fn snmp_interface(&mut self) -> &mut Self::Interface {
        self
    }
}

// ----------------------------------- GENERATED ------------------------------------
// Per MIB

declare_oid!("ipAddress", std::net::Ipv4Addr);
declare_mib!("EXAMPLE-MIB.mib");

// Per OID (overall)

// Per OID per MIB
impl<'a, I: SnmpInterface> ReadIpAddress for ExampleMib<'a, I> {
    const OID: ConstOid = ConstOid(&[1_u32, 3_u32, 6_u32, 1_u32, 4_u32, 1_u32]);
}

//     where ip_address is implemented by trait GetIpAddressOid generated from an OID called ipAddress
//     this trait is implemented on MyMibName
//     this method returns IpAddress

fn x<T: SnmpInterface>(mut x: T) {
    x.example_mib().ip_address();
} 


trait AsOid {
    fn as_oid(&self) -> ObjectIdentifier;
}

enum Error {

}

trait Mib {
    const OID: ObjectIdentifier;
}

trait ScalarMib: Mib {
    type Value: TryFrom<snmp::v2::ObjectSyntax, Error = Error> + TryInto<snmp::v2::ObjectSyntax, Error = Error>; 
}

trait ReadableMib: ScalarMib {
    fn get(&self) -> Self::Value;
}

trait WriteableMib: ScalarMib {
    fn set(&mut self, value: &Self::Value) -> Result<(), Error>;
}

trait IndexedScalarMib: ScalarMib {
    type Index: TryFrom<ObjectIdentifier, Error = Error> + TryInto<ObjectIdentifier, Error = Error>;
}

trait ReadableAtMib: IndexedScalarMib {
    fn get(&self, index: &Self::Index) -> Result<Self::Value, Error>;
}

trait WriteableAtMib: IndexedScalarMib {
    fn set(&self, index: &Self::Index, value: &Self::Value) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
