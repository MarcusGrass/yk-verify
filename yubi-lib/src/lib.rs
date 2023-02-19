#![warn(clippy::pedantic)]
#![deny(unsafe_code)]
extern crate alloc;
extern crate core;

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use p384::ecdsa::signature::digest::{Digest, FixedOutput};
use p384::ecdsa::{Signature, VerifyingKey};
use p384::elliptic_curve::sec1::FromEncodedPoint;
use p384::pkcs8::DecodePublicKey;
use p384::{EncodedPoint, PublicKey};
use pcsc::{Context, Protocols, Scope, ShareMode, Transaction};
use signature::Verifier;

use crate::error::{Error, Result};

mod error;

pub(crate) const INS_SEND_REMAINING: u8 = 0xC0;
pub(crate) const INS_GET_METADATA: u8 = 0xF7;
pub(crate) const INS_AUTHENTICATE: u8 = 0x87;
pub(crate) const INS_VERIFY_PIN: u8 = 0x20;
pub(crate) const TAG_METADATA_ALGO: u8 = 0x01;
pub(crate) const TAG_METADATA_POLICY: u8 = 0x02;
pub(crate) const TAG_METADATA_ORIGIN: u8 = 0x03;
pub(crate) const TAG_METADATA_PUBLIC_KEY: u8 = 0x04;
pub(crate) const TAG_DYN_AUTH: u8 = 0x7C;
pub(crate) const TAG_AUTH_CHALLENGE: u8 = 0x81;
pub(crate) const TAG_AUTH_RESPONSE: u8 = 0x82;
pub(crate) const PIN_P2: u8 = 0x80;
pub(crate) const SW1_HAS_MORE_DATA: u8 = 0x61;
pub(crate) const AID_PIV: &[u8] = b"\xa0\x00\x00\x03\x08";
pub(crate) const MAX_PIN_LEN: usize = 8;

/// Verify an ECP384 key on `slot`'s signature against a generated random message using any of the provided
/// public key pem file contents provided in `pub_keys`.  
/// # Errors
/// 1. Yubikey is not configured with an ECP384 key in the provided `slot`.  
/// 2. Errors using the `pcsc`-daemon to find and connect to the Yubikey.  
/// 3. Error prompting for the PIN, if configured.  
/// 4. Error not receiving touch within timeout, if configured.  
/// 5. Error generating random message.  
/// 6. Error decoding provided certificates.  
///
#[allow(clippy::too_many_lines)]
pub fn verify_signature(pub_keys: &[String], slot: u8) -> Result<()> {
    let ctx = Context::establish(Scope::System)
        .map_err(|e| Error::Verify(format!("Failed to establish context {e}, common causes are: \n\t1. pcscd not running\n\t2. Something else has exclusive access to the smartcard")))?;
    let lr_len = ctx
        .list_readers_len()
        .map_err(|e| Error::Verify(format!("Failed to get readers len {e}")))?;
    let mut reader_buf = vec![0u8; lr_len];
    for reader in ctx
        .list_readers(&mut reader_buf)
        .map_err(|e| Error::Verify(format!("Failed to list smart cards {e}")))?
    {
        let utf8 = reader
            .to_str()
            .map_err(|e| Error::Verify(format!("Failed to decode reader name as utf8 {e}")))?;
        if utf8.to_lowercase().starts_with("yubico yubikey") {
            println!("Found card {utf8}");
            let mut card = ctx
                .connect(reader, ShareMode::Exclusive, Protocols::ANY)
                .map_err(|e| {
                    Error::Verify(format!("Failed to connect to card {utf8}, error: {e}"))
                })?;
            let tx = card.transaction().map_err(|e| {
                Error::Verify(format!(
                    "Failed to initiate a transaction with card {utf8}, error: {e}"
                ))
            })?;
            select(&tx, AID_PIV).map_err(|e| {
                Error::Verify(format!("Failed to select PIV on card {utf8}, error: {e}"))
            })?;
            let slot_meta = get_slot_metadata(&tx, slot).map_err(|e| {
                Error::Verify(format!(
                    "Failed to get metadata for slot {slot:X} on card {utf8}, error: {e}"
                ))
            })?;
            if slot_meta.key_type != KeyType::ECCP384 {
                return Err(Error::Verify(format!("Found unsupported key type '{:?}' in slot {slot:X?}, only '{:?}' is supported.", slot_meta.key_type, KeyType::ECCP384)));
            }
            let Some(pub_key) = slot_meta.public_key_der else {
                return Err(Error::Verify(format!("No public key in slot {slot:X} for card {utf8}")));
            };
            if slot_meta.pin_policy != PinPolicy::Never {
                let pin = rpassword::prompt_password(format!(
                    "Found Pin policy \"{:?}\", please enter pin: ",
                    slot_meta.pin_policy
                ))
                .map_err(|e| Error::Verify(format!("Failed to read pin from cmdline {e}")))?;
                verify_pin(&tx, &pin)
                    .map_err(|e| Error::Verify(format!("Failed to verify pin {e}")))?;
                println!("Pin verified.");
            }

            let mut msg = [0u8; 1024];
            // Seed doesn't really have to be secure
            let mut rng = oorandom::Rand64::new(SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| Error::Bug(format!("Failed to get systemtime since UNIX_EPOCH, you're system is probably broken. {e}")))?
                .as_nanos()
            );
            for i in (0..1024usize).step_by(8) {
                let end_ind = i.checked_add(8)
                    .ok_or_else(|| Error::Bug("Usize overflow when incrementing index by 8".to_string()))?;
                msg.get_mut(i..end_ind)
                    .ok_or_else(|| Error::Bug(format!("Index out of range trying to write bytes into message to sign")))?
                    .copy_from_slice(&rng.rand_u64().to_ne_bytes())
            }
            println!("Generated 1024 byte message, starting signing operation.");
            if slot_meta.touch_policy != TouchPolicy::Never {
                println!(
                    "Found touch policy \"{:?}\", please touch the smartcard.",
                    slot_meta.touch_policy
                );
            }
            let signature_msg = sign(&tx, &msg)
                .map_err(|e| Error::Verify(format!("Failed to sign message {e}")))?;
            let sig = &signature_msg.get(4..).ok_or_else(|| {
                Error::Verify("Got bad signature response, response too short".to_string())
            })?;
            let p384_sig = Signature::from_der(sig).map_err(|e| {
                Error::Verify(format!("Failed to decode signature as p384-der {e}"))
            })?;
            let on_card_encoded_point = pub_key.get(2..).ok_or_else(|| {
                Error::Verify("Public key from card has too few bytes".to_string())
            })?;
            let encoded_point: EncodedPoint = EncodedPoint::from_bytes(on_card_encoded_point)
                .map_err(|e| {
                    Error::Verify(format!(
                        "Failed to decode encoded point for public key: '{e}'"
                    ))
                })?;

            // Custom option type with lacking conversion methods, nice.
            let maybe_pk = PublicKey::from_encoded_point(&encoded_point);
            if maybe_pk.is_some().unwrap_u8() == 0 {
                return Err(Error::Verify(
                    "Failed to convert encoded point found on card to a p384 public key"
                        .to_string(),
                ));
            }
            let on_card_pk = maybe_pk.unwrap();
            for (ind, pk) in pub_keys.iter().enumerate() {
                let verify_against_pk = PublicKey::from_public_key_pem(pk).map_err(|e| {
                    Error::Verify(format!(
                        "Failed to decode supplied public key as p384-pem {e}"
                    ))
                })?;
                if on_card_pk == verify_against_pk {
                    println!("Verifying signature against public key at index {ind}");
                    let verify_key = VerifyingKey::from(verify_against_pk);
                    verify_key
                        .verify(&msg, &p384_sig)
                        .map_err(|e| Error::Verify(format!("Signature verification failed {e}")))?;
                    println!("Signature verified.");
                    return Ok(());
                }
            }
            println!("Card {utf8} did not carry any of the public keys to match against.");
        }
    }
    Err(Error::Verify(
        "Found no cards carrying keys matching the supplied public keys".to_string(),
    ))
}

fn sign(tx: &Transaction, msg: &[u8]) -> Result<Vec<u8>> {
    let mut ret = vec![0; 1024];
    let mut payload = into_ttlv(TAG_AUTH_RESPONSE, &[])?;
    let mut sha = sha2::Sha384::default();
    sha.update(msg);
    let mut msg_sha = sha.finalize_fixed().to_vec();
    let byte_len = 384 / 8;
    if msg_sha.len() < byte_len {
        msg_sha.resize(byte_len, 0);
    }
    let msg = &msg_sha.as_slice().get(..byte_len)
        .ok_or_else(|| Error::Bug(format!("Sha digest shorter than {byte_len}")))?;

    payload.extend(into_ttlv(TAG_AUTH_CHALLENGE, msg)?);
    let data = into_ttlv(TAG_DYN_AUTH, &payload)?;
    let ret = send_apdu(
        tx,
        0x00,
        INS_AUTHENTICATE,
        0x14,
        0x9a,
        &data,
        &mut ret,
        false,
        INS_SEND_REMAINING,
    )?;
    Ok(ret)
}

fn verify_pin(tx: &Transaction, pin: &str) -> Result<()> {
    let bytes = pin.as_bytes();
    let bytes_len = bytes.len();
    if bytes_len > MAX_PIN_LEN {
        return Err(Error::Piv(format!(
            "Piv pin too long, max length is 8 bytes, supplied {bytes_len} bytes"
        )));
    }
    let mut pin_bytes = [0xFFu8; MAX_PIN_LEN];
    pin_bytes
        .get_mut(..bytes_len)
        .ok_or_else(|| {
            Error::Bug(format!(
                "Failed to get first {bytes_len} bytes from pin_bytes array"
            ))
        })?
        .copy_from_slice(bytes);
    let mut ret = [0u8; 64];
    send_apdu(
        tx,
        0,
        INS_VERIFY_PIN,
        0,
        PIN_P2,
        &pin_bytes,
        &mut ret,
        false,
        INS_SEND_REMAINING,
    )?;
    Ok(())
}

fn get_slot_metadata(tx: &Transaction, slot: u8) -> Result<SlotMetadata> {
    let mut ret = [0u8; 512];
    let apdu_result = send_apdu(
        tx,
        0,
        INS_GET_METADATA,
        0,
        slot,
        &[],
        &mut ret,
        false,
        INS_SEND_REMAINING,
    )?;
    parse_slot_metadata(&apdu_result)
}

fn parse_slot_metadata(data: &[u8]) -> Result<SlotMetadata> {
    let mut key_type = None;
    let mut touch_policy = None;
    let mut pin_policy = None;
    let mut generated_on_card = None;
    let mut public_key_der = None;
    consume_ttlvs(data, |ttlv| {
        match ttlv.tag {
            TAG_METADATA_ALGO => {
                if ttlv.value.len() != 1 {
                    return Err(Error::Protocol(format!(
                        "Tag metadata algo has unexpected value length != 1: {}",
                        ttlv.value.len()
                    )));
                }
                key_type = Some(KeyType::try_from(*ttlv.value.first().ok_or_else(
                    || {
                        Error::Bug(
                            "Failed to get value from a ttlv value checked to have length == 1"
                                .to_string(),
                        )
                    },
                )?)?);
            }
            TAG_METADATA_POLICY => {
                if ttlv.value.len() != 2 {
                    return Err(Error::Protocol(format!(
                        "Tag metadata policy has unexpected value length != 2: {}",
                        ttlv.value.len()
                    )));
                }
                pin_policy = Some(PinPolicy::try_from(*ttlv.value.first().ok_or_else(
                    || {
                        Error::Bug(
                            "Failed to get first byte from ttlv value checked to have length 2"
                                .to_string(),
                        )
                    },
                )?)?);
                touch_policy = Some(TouchPolicy::try_from(*ttlv.value.get(1).ok_or_else(
                    || {
                        Error::Bug(
                            "Failed to get second byte from ttlv value checked to have length 2"
                                .to_string(),
                        )
                    },
                )?)?);
            }
            TAG_METADATA_ORIGIN => {
                if ttlv.value.len() != 1 {
                    return Err(Error::Protocol(format!(
                        "Tag metadata origin has unexpected value length != 1: {}",
                        ttlv.value.len()
                    )));
                }
                generated_on_card = Some(
                    *ttlv.value.first().ok_or_else(|| {
                        Error::Bug(
                            "Failed to get value from ttlv value with a length checked to be 1"
                                .to_string(),
                        )
                    })? == 1,
                );
            }
            TAG_METADATA_PUBLIC_KEY => {
                public_key_der = Some(ttlv.value.to_vec());
            }
            _ => {}
        }
        Ok(())
    })?;

    Ok(SlotMetadata {
        key_type: key_type
            .ok_or_else(|| Error::Protocol("Key type missing from key response".to_string()))?,
        touch_policy: touch_policy
            .ok_or_else(|| Error::Protocol("Touch policy missing from key response".to_string()))?,
        pin_policy: pin_policy
            .ok_or_else(|| Error::Protocol("Pin policy missing from key response".to_string()))?,
        _generated_on_card: generated_on_card,
        public_key_der,
    })
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum KeyType {
    PinOrPuk = 0xFF,
    TDES = 0x03,
    AES128 = 0x08,
    AES192 = 0x0A,
    AES256 = 0x0C,
    RSA1024 = 0x06,
    RSA2048 = 0x07,
    ECCP256 = 0x11,
    ECCP384 = 0x14,
}

impl TryFrom<u8> for KeyType {
    type Error = Error;

    #[inline]
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            0xFF => Self::PinOrPuk,
            0x03 => Self::TDES,
            0x08 => Self::AES128,
            0x0A => Self::AES192,
            0x0C => Self::AES256,
            0x06 => Self::RSA1024,
            0x07 => Self::RSA2048,
            0x11 => Self::ECCP256,
            0x14 => Self::ECCP384,
            _ => {
                return Err(Error::Protocol(format!("Got invalid key type {value:X}")));
            }
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum TouchPolicy {
    Default = 0x0,
    Never = 0x1,
    Always = 0x2,
    Cached = 0x3,
}

impl TryFrom<u8> for TouchPolicy {
    type Error = Error;

    #[inline]
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            0 => TouchPolicy::Default,
            1 => TouchPolicy::Never,
            2 => TouchPolicy::Always,
            3 => TouchPolicy::Cached,
            _ => {
                return Err(Error::Protocol(format!(
                    "Failed to parse touch policy, unexpected value {value:X}"
                )));
            }
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum PinPolicy {
    Default = 0x0,
    Never = 0x1,
    Once = 0x2,
    Always = 0x3,
}

impl TryFrom<u8> for PinPolicy {
    type Error = Error;

    #[inline]
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            0 => PinPolicy::Default,
            1 => PinPolicy::Never,
            2 => PinPolicy::Once,
            3 => PinPolicy::Always,
            _ => {
                return Err(Error::Protocol(format!(
                    "Failed to parse pin policy, unexpected value {value:X}"
                )));
            }
        })
    }
}

#[derive(Debug)]
struct SlotMetadata {
    key_type: KeyType,
    touch_policy: TouchPolicy,
    pin_policy: PinPolicy,
    _generated_on_card: Option<bool>,
    public_key_der: Option<Vec<u8>>,
}

fn into_ttlv(tag: u8, value: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![];
    out.push(tag);
    let v_len = value.len();
    if v_len < 0x80 {
        out.push(v_len.try_into().map_err(|e| {
            Error::Bug(format!(
                "Can't convert usize to u8 after checking it's less than 0x80 {v_len} {e}"
            ))
        })?);
    } else {
        let l2b = encode_length_to_be_bytes(v_len)?;
        let l2b_len: u8 = l2b
            .len()
            .try_into()
            // Kind of nonsensical error, if the length needs more than a u8::MAX bytes to encode
            // this operation will fail elsewhere.
            .map_err(|e| {
                Error::Protocol(format!(
                    "Got nonsensical byte-length larger than u8::MAX bytes {e}"
                ))
            })?;
        out.push(0x80 | l2b_len);
        out.extend(l2b);
    }
    out.extend(value);
    Ok(out)
}

#[derive(Debug)]
struct UnpackedTtlv<'a> {
    tag: u8,
    value: &'a [u8],
    end: usize,
}

fn consume_ttlvs<F: FnMut(UnpackedTtlv) -> Result<()>>(
    data: &[u8],
    mut ttlv_consumer: F,
) -> Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        let ttlv = unpack_ttlv(data, offset)?;
        offset = ttlv.end;
        (ttlv_consumer)(ttlv)?;
    }
    Ok(())
}

// Der encoding
fn unpack_ttlv(data: &[u8], mut offset: usize) -> Result<UnpackedTtlv> {
    let tag = *data
        .get(offset)
        .ok_or_else(|| Error::Arithmetic("No tag byte in ttlv".to_string()))?;
    offset = offset
        .checked_add(1)
        .ok_or_else(|| Error::Bug("Offset overflowed a usize".to_string()))?;
    if tag & 0x1F == 0x1F {
        // Long form not supported
        return Err(Error::Arithmetic(
            "Long form ttlv tag not supported".to_string(),
        ));
    }
    let mut len = *data
        .get(offset)
        .ok_or_else(|| Error::Arithmetic("No len byte in ttlv".to_string()))?
        as usize;
    offset = offset
        .checked_add(1)
        .ok_or_else(|| Error::Bug("Offset overflowed a usize".to_string()))?;
    let end = match len.cmp(&0x80) {
        Ordering::Less => offset.checked_add(len)
            .ok_or_else(|| Error::Bug(format!("Offset {offset} + len {len} overflowed a usize when trying to calculate end of message")))?,
        Ordering::Equal => {
            return Err(Error::Arithmetic(
                "Indefinite length not supported".to_string(),
            ));
        }
        Ordering::Greater => {
            let num_bytes = len
                .checked_sub(0x80)
                .ok_or_else(|| Error::Bug(format!("Subtracting {} from len {len} which was checked to be larger than {} underflowed.", 0x80, 0x80)))?;
            let msg_off = offset.checked_add(num_bytes)
                .ok_or_else(|| Error::Bug(format!("Offset {offset} + num_bytes in length message {num_bytes} overflowed a usize when trying to calculate end of message")))?;
            len =
                decode_be_bytes_to_len(data.get(offset..msg_off).ok_or_else(|| {
                    Error::Arithmetic("Not enough bytes to decode length".to_string())
                })?)?;
            offset = msg_off;
            offset.checked_add(len)
                .ok_or_else(|| Error::Bug(format!("Offset {offset} + len {len} overflowed a usize when trying to calculate end of message")))?
        }
    };
    Ok(UnpackedTtlv {
        tag,
        value: data.get(offset..end)
            .ok_or_else(|| Error::Bug(format!("Calculated end of message {end} out of bounds")))?,
        end,
    })
}

fn encode_length_to_be_bytes(mut l: usize) -> Result<Vec<u8>> {
    let mut buf = vec![];
    while l > 0xFF {
        let l_byte: u8 = (l & 0xFF)
            .try_into()
            .map_err(|e| Error::Protocol(format!("Failed to encode length {l} to be bytes {e}")))?;
        buf.push(l_byte);
        l >>= 8;
    }
    let l_byte: u8 = (l & 0xFF)
        .try_into()
        .map_err(|e| Error::Protocol(format!("Failed to encode length {l} to be bytes {e}")))?;
    buf.push(l_byte);
    Ok(buf)
}

fn decode_be_bytes_to_len(bytes: &[u8]) -> Result<usize> {
    Ok(match bytes.len() {
        1 => *bytes.first().ok_or_else(|| {
            Error::Bug("Could not get first byte of array checked to have length == 1".to_string())
        })? as usize,
        2 => u16::from_be_bytes(
            bytes
                .get(0..2)
                .ok_or_else(|| {
                    Error::Bug(
                        "Could not get first two bytes of array checked to have length == 2"
                            .to_string(),
                    )
                })?
                .try_into()
                .map_err(|e| Error::Bug(format!("Could not convert two bytes to a [u8;2] {e}")))?,
        ) as usize,
        4 => u32::from_be_bytes(
            bytes
                .get(0..4)
                .ok_or_else(|| {
                    Error::Bug(
                        "Could not get first four bytes of array checked to have length == 4"
                            .to_string(),
                    )
                })?
                .try_into()
                .map_err(|e| Error::Bug(format!("Could not convert four bytes to a [u8;4] {e}")))?,
        ) as usize,
        n => {
            return Err(Error::Arithmetic(format!(
                "Got bad byte length to decode {n} (max 4 bytes and a power of 2 supported)"
            )));
        }
    })
}

#[inline]
fn select(tx: &Transaction, aid: &[u8]) -> Result<()> {
    // Just 4 bytes of data, 2 bytes of SWs
    let mut select_buf = [0u8; 32];
    send_apdu(
        tx,
        0,
        0xA4,
        0x04,
        0x00,
        aid,
        &mut select_buf,
        false,
        INS_SEND_REMAINING,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[inline]
fn send_apdu(
    tx: &Transaction,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    mut data: &[u8],
    ret_buf: &mut [u8],
    long: bool,
    ins_send_remaining: u8,
) -> Result<Vec<u8>> {
    const SHORT_APDU_MAX_CHUNK: usize = 0xFF;
    if long {
        let encoded = encode_long(cla, ins, p1, p2, data)?;
        let resp = tx
            .transmit(&encoded, ret_buf)
            .map_err(|e| Error::Transport(format!("Got transmit error sending APDU {e}")))?
            .to_vec();
        let (resp_data, mut sw1, mut sw2) = parse_response(&resp)?;
        let mut resp_data = if let Some(resp) = resp_data {
            resp.to_vec()
        } else {
            vec![]
        };
        if sw1 == SW1_HAS_MORE_DATA {
            let get_data = encode_long(0, ins_send_remaining, 0, 0, &[])?;
            let get_more_resp = tx.transmit(&get_data, &mut ret_buf[resp.len()..])?;
            let (more_resp_data, more_sw1, more_sw2) = parse_response(get_more_resp)?;

            if let Some(more) = more_resp_data {
                resp_data.extend_from_slice(more);
            }
            sw1 = more_sw1;
            sw2 = more_sw2;
        }
        if !sw_ok(sw1, sw2) {
            return Err(Error::Apdu(
                format!("Got non-ok response on apdu CLA {cla}, sw1 = {sw1}, sw2 = {sw2}"),
                sw1,
                sw2,
            ));
        }
        Ok(resp_data)
    } else {
        while data.len() > SHORT_APDU_MAX_CHUNK {
            let chunk = &data[..SHORT_APDU_MAX_CHUNK];
            data = &data[SHORT_APDU_MAX_CHUNK..];
            let encoded = encode_short(0x10 | cla, ins, p1, p2, chunk)?;
            let resp = tx.transmit(&encoded, ret_buf).unwrap();
            let (resp_data, sw1, sw2) = parse_response(resp)?;
            if !sw_ok(sw1, sw2) {
                return Err(Error::Apdu(format!("Got non-ok response sending short APDU on CLA {cla:X}, INS {ins:X}, sw1 = {sw1:X}, sw2 = {sw2:X}, response {resp_data:?}"), sw1, sw2));
            }
        }
        let encoded = encode_short(cla, ins, p1, p2, data)?;
        let resp = tx.transmit(&encoded, ret_buf).unwrap().to_vec();
        let (resp_data, mut sw1, mut sw2) = parse_response(&resp)?;
        let mut resp_data = if let Some(resp) = resp_data {
            resp.to_vec()
        } else {
            vec![]
        };
        if sw1 == SW1_HAS_MORE_DATA {
            let get_data = encode_short(0, ins_send_remaining, 0, 0, &[])?;
            let get_more_resp = tx.transmit(&get_data, &mut ret_buf[resp.len()..])?;
            let (more_resp_data, more_sw1, more_sw2) = parse_response(get_more_resp)?;

            if let Some(more) = more_resp_data {
                resp_data.extend_from_slice(more);
            }
            sw1 = more_sw1;
            sw2 = more_sw2;
        }
        if !sw_ok(sw1, sw2) {
            return Err(Error::Apdu(format!("Got non-ok response sending short APDU on CLA {cla:X}, INS {ins:X}, sw1 = {sw1:X}, sw2 = {sw2:X}, response {resp_data:?}"), sw1, sw2));
        }
        Ok(resp_data)
    }
}

#[inline]
fn encode_short(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>> {
    let sz: u8 = data
        .len()
        .try_into()
        // Should never happen since we check the chunk size.
        .map_err(|e| Error::Protocol(format!("Failed to encode short APDU packet size: {e}")))?;
    // Can't overflow a usize here since data.len() < 256
    let mut buf = Vec::with_capacity(5 + data.len());
    buf.extend_from_slice(&[cla.to_be(), ins.to_be(), p1.to_be(), p2.to_be(), sz.to_be()]);
    buf.extend_from_slice(data);
    Ok(buf)
}

#[inline]
fn encode_long(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>> {
    let sz: u8 = data
        .len()
        .try_into()
        .map_err(|e| Error::Protocol(format!("Failed to encode long APDU packet size: {e}")))?;
    // Can't overflow a usize here since data.len() < 256
    let mut buf = Vec::with_capacity(7 + data.len());
    let pad = 0u16.to_be_bytes();
    buf.extend_from_slice(&[
        cla.to_be(),
        ins.to_be(),
        p1.to_be(),
        p2.to_be(),
        pad[0],
        pad[1],
        sz.to_be(),
    ]);
    buf.extend_from_slice(data);
    Ok(buf)
}

#[inline]
fn parse_response(raw: &[u8]) -> Result<(Option<&[u8]>, u8, u8)> {
    let len = raw.len();
    match len.cmp(&2) {
        Ordering::Less => {
            return Err(Error::Transport(format!(
                "Got apdu response shorter than 2 bytes {raw:?}",
            )));
        }
        Ordering::Equal => Ok((
            None,
            *raw.first().ok_or_else(|| {
                Error::Bug(
                    "Could not get index 0 of respone after checking length == 2".to_string(),
                )
            })?,
            *raw.get(1).ok_or_else(|| {
                Error::Bug(
                    "Could not get index 1 of respone after checking length == 2".to_string(),
                )
            })?,
        )),
        Ordering::Greater => {
            let up_to_last_two_ind = len.checked_sub(2)
                .ok_or_else(|| Error::Bug("Could not get second to last index on an array checked to have a length greater than 2".to_string()))?;
            let last_value_ind = len.checked_sub(1).ok_or_else(|| {
                Error::Bug(
                    "Could not get last index on an array checked to have a length greater than 2"
                        .to_string(),
                )
            })?;
            Ok((
                Some(
                    raw.get(..up_to_last_two_ind)
                        .ok_or_else(|| Error::Bug("Could not get all values up until the last two on an array with length > 2".to_string()))?,
                ),
                *raw.get(up_to_last_two_ind)
                    .ok_or_else(|| Error::Bug("Could not get second to last value in an array checked to have a length greater than 2".to_string()))?,
                *raw.get(last_value_ind)
                    .ok_or_else(|| Error::Bug("Could not get last value in an array checked to have a length greater than 2".to_string()))?,
            ))
        }
    }
}

#[inline]
fn sw_ok(sw1: u8, sw2: u8) -> bool {
    sw1 == 0x90 && sw2 == 0x00
}

#[cfg(test)]
mod tests {
    use ecdsa::elliptic_curve::pkcs8::DecodePublicKey;
    use p384::elliptic_curve::sec1::FromEncodedPoint;
    use p384::elliptic_curve::PublicKey;
    use p384::{EncodedPoint, NistP384};

    use crate::{parse_slot_metadata, KeyType, PinPolicy, TouchPolicy};

    #[test]
    fn decode_slot() {
        // Example yk response
        let example: [u8; 111] = [
            1, 1, 20, 2, 2, 3, 3, 3, 1, 1, 4, 99, 134, 97, 4, 123, 47, 71, 187, 144, 68, 176, 177,
            17, 129, 224, 79, 255, 214, 187, 178, 227, 170, 131, 129, 22, 110, 53, 178, 20, 193,
            61, 96, 36, 27, 118, 186, 82, 247, 101, 202, 8, 182, 128, 139, 170, 225, 76, 78, 207,
            208, 157, 59, 58, 196, 0, 49, 151, 195, 218, 253, 93, 168, 249, 75, 81, 193, 227, 20,
            109, 158, 21, 92, 31, 29, 192, 17, 57, 100, 161, 113, 0, 156, 177, 12, 20, 244, 6, 26,
            215, 54, 32, 208, 231, 152, 92, 4, 240, 68, 123, 206,
        ];
        // Corresponding pub key pem file
        let known_pub_key: &str = "-----BEGIN PUBLIC KEY-----\n\
        MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEey9Hu5BEsLERgeBP/9a7suOqg4EWbjWy\n\
        FME9YCQbdrpS92XKCLaAi6rhTE7P0J07OsQAMZfD2v1dqPlLUcHjFG2eFVwfHcAR\n\
        OWShcQCcsQwU9AYa1zYg0OeYXATwRHvO\n\
        -----END PUBLIC KEY-----\n";

        let md = parse_slot_metadata(&example).unwrap();
        let saved_key = PublicKey::from_public_key_pem(known_pub_key).unwrap();
        let ep: EncodedPoint = EncodedPoint::from_bytes(&md.public_key_der.unwrap()[2..]).unwrap();
        let pkey: PublicKey<NistP384> = PublicKey::from_encoded_point(&ep).unwrap();
        assert_eq!(KeyType::ECCP384, md.key_type);
        assert_eq!(TouchPolicy::Cached, md.touch_policy);
        assert_eq!(PinPolicy::Always, md.pin_policy);
        assert!(md._generated_on_card.unwrap());
        assert_eq!(saved_key, pkey);
    }
}
