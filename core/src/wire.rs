//! Wire format of everything that leaves or enters the wallet.
//!
//! Every payload is one self-describing binary blob:
//!
//! ```text
//! magic (3) | version (1) | kind (1) | body | checksum (4)
//! ```
//!
//! `checksum` is the first four bytes of SHA-256 over everything before it,
//! so a mistyped or truncated string is rejected before it reaches the
//! protocol. The magic is chosen so that the base64 text form of every blob
//! starts with `FRST`. The same base64 text is what goes into a QR code, a
//! file and the clipboard.
//!
//! Integers are big-endian, points are 33-byte compressed SEC1, scalars are
//! 32 bytes. The recovery data body is byte-compatible with the ChillDKG
//! reference (`transcript || cert`).

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chilldkg_rs::crypto::certeq::CertEQTranscript;
use chilldkg_rs::crypto::ec::{
    compress_default, decompress_default, parse_scalar_from_bytes, parse_secret_scalar_from_bytes,
};
use chilldkg_rs::dkg::msg::{
    CoordinatorMsg1, CoordinatorMsg2, DKGOutput, ParticipantMsg1, ParticipantMsg2, RecoveryData,
};
use chilldkg_rs::sign::{PubNonce, Tweak};
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Base64 of these three bytes is `FRST`.
pub const MAGIC: [u8; 3] = [0x15, 0x14, 0x93];
pub const VERSION: u8 = 1;

/// Upper bound on the number of participants a blob may describe. Passing
/// messages by hand does not scale anywhere near this; it only bounds
/// allocations while decoding.
pub const MAX_PARTICIPANTS: usize = 255;
/// Upper bound on the size of a message to sign carried inside a blob.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;
pub const MAX_TWEAKS: usize = 16;

pub type SessionId = [u8; 8];

const POINT: usize = 33;
const SCALAR: usize = 32;
const SIG: usize = 64;

mod kind {
    pub const HOST_SECRET: u8 = 0x01;
    pub const HOST_PUBLIC: u8 = 0x02;
    pub const DKG_PARAMS: u8 = 0x10;
    pub const DKG_P1: u8 = 0x11;
    pub const DKG_C1: u8 = 0x12;
    pub const DKG_P2: u8 = 0x13;
    pub const DKG_C2: u8 = 0x14;
    pub const RECOVERY: u8 = 0x20;
    pub const SHARE: u8 = 0x21;
    pub const SIGN_REQUEST: u8 = 0x30;
    pub const SIGN_NONCE: u8 = 0x31;
    pub const SIGN_PACKAGE: u8 = 0x32;
    pub const SIGN_PARTIAL: u8 = 0x33;
    pub const SIGNATURE: u8 = 0x34;
}

pub enum Blob {
    /// A participant's long-term host secret key. Secret.
    HostSecret(Zeroizing<Scalar>),
    /// A participant's host public key, sent to the coordinator before a DKG.
    HostPublic(ProjectivePoint),
    /// DKG session parameters, coordinator -> participants.
    DkgParams {
        sid: SessionId,
        t: usize,
        hosts: Vec<ProjectivePoint>,
    },
    /// DKG round 1, participant -> coordinator.
    DkgP1 {
        sid: SessionId,
        idx: usize,
        msg: ParticipantMsg1,
    },
    /// DKG round 1, coordinator -> participants.
    DkgC1 {
        sid: SessionId,
        msg: CoordinatorMsg1,
    },
    /// DKG round 2, participant -> coordinator.
    DkgP2 {
        sid: SessionId,
        idx: usize,
        msg: ParticipantMsg2,
    },
    /// DKG certificate, coordinator -> participants.
    DkgC2 {
        sid: SessionId,
        msg: CoordinatorMsg2,
    },
    /// Public recovery data of a finished DKG.
    Recovery(RecoveryData),
    /// A participant's DKG output, secret share included. Secret.
    Share(DKGOutput),
    /// Signing request, coordinator -> signers.
    SignRequest {
        ssid: SessionId,
        group: ProjectivePoint,
        msg: Vec<u8>,
        tweaks: Vec<Tweak>,
    },
    /// Signing round 1, signer -> coordinator.
    SignNonce {
        ssid: SessionId,
        idx: usize,
        nonce: PubNonce,
    },
    /// Signing round 2, coordinator -> signers: the nonces of the signing set.
    SignPackage {
        ssid: SessionId,
        nonces: Vec<(usize, PubNonce)>,
    },
    /// Signing round 2, signer -> coordinator.
    SignPartial {
        ssid: SessionId,
        idx: usize,
        psig: Scalar,
    },
    /// A finished BIP340 signature together with what it signs.
    Signature {
        pubkey: [u8; 32],
        sig: [u8; SIG],
        msg: Vec<u8>,
    },
}

impl Blob {
    /// Short human name of the blob kind, used in messages to the user.
    pub fn title(&self) -> &'static str {
        match self {
            Blob::HostSecret(_) => "host secret key backup",
            Blob::HostPublic(_) => "host public key",
            Blob::DkgParams { .. } => "key generation parameters",
            Blob::DkgP1 { .. } => "key generation round 1 message (participant)",
            Blob::DkgC1 { .. } => "key generation round 1 message (coordinator)",
            Blob::DkgP2 { .. } => "key generation round 2 message (participant)",
            Blob::DkgC2 { .. } => "key generation certificate",
            Blob::Recovery(_) => "recovery data",
            Blob::Share(_) => "key share backup",
            Blob::SignRequest { .. } => "signing request",
            Blob::SignNonce { .. } => "signing nonce",
            Blob::SignPackage { .. } => "signing package",
            Blob::SignPartial { .. } => "partial signature",
            Blob::Signature { .. } => "signature",
        }
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new(self.kind());
        match self {
            Blob::HostSecret(s) => w.secret_scalar(s),
            Blob::HostPublic(p) => w.point(p),
            Blob::DkgParams { sid, t, hosts } => {
                w.bytes(sid);
                w.u16(*t);
                w.u16(hosts.len());
                w.points(hosts);
            }
            Blob::DkgP1 { sid, idx, msg } => {
                w.bytes(sid);
                w.u16(*idx);
                w.u16(msg.commitment.len());
                w.u16(msg.enc_shares.len());
                w.points(&msg.commitment);
                w.bytes(&msg.pop);
                w.point(&msg.pubnonce);
                w.scalars(&msg.enc_shares);
            }
            Blob::DkgC1 { sid, msg } => {
                w.bytes(sid);
                w.u16(msg.coms_to_secrets.len());
                w.u16(msg.sum_coms_to_nonconst_terms.len());
                w.points(&msg.coms_to_secrets);
                w.points(&msg.sum_coms_to_nonconst_terms);
                for pop in &msg.pops {
                    w.bytes(pop);
                }
                w.points(&msg.pubnonces);
                w.scalars(&msg.enc_secshares);
            }
            Blob::DkgP2 { sid, idx, msg } => {
                w.bytes(sid);
                w.u16(*idx);
                w.bytes(&msg.sig);
            }
            Blob::DkgC2 { sid, msg } => {
                w.bytes(sid);
                w.u16(msg.cert.len());
                for sig in &msg.cert {
                    w.bytes(sig);
                }
            }
            Blob::Recovery(r) => {
                w.bytes(&Vec::<u8>::from(&r.transcript));
                for sig in &r.cert {
                    w.bytes(sig);
                }
            }
            Blob::Share(o) => {
                w.u16(o.idx);
                w.u16(o.t);
                w.u16(o.pubshares.len());
                w.secret_scalar(&o.secshare);
                w.point(&o.threshold_pubkey);
                w.points(&o.pubshares);
            }
            Blob::SignRequest {
                ssid,
                group,
                msg,
                tweaks,
            } => {
                w.bytes(ssid);
                w.point(group);
                w.u8(tweaks.len());
                for tweak in tweaks {
                    w.u8(usize::from(tweak.is_xonly));
                    w.bytes(&tweak.value);
                }
                w.u32(msg.len());
                w.bytes(msg);
            }
            Blob::SignNonce { ssid, idx, nonce } => {
                w.bytes(ssid);
                w.u16(*idx);
                w.point(&nonce.R1);
                w.point(&nonce.R2);
            }
            Blob::SignPackage { ssid, nonces } => {
                w.bytes(ssid);
                w.u16(nonces.len());
                for (idx, nonce) in nonces {
                    w.u16(*idx);
                    w.point(&nonce.R1);
                    w.point(&nonce.R2);
                }
            }
            Blob::SignPartial { ssid, idx, psig } => {
                w.bytes(ssid);
                w.u16(*idx);
                w.scalar(psig);
            }
            Blob::Signature { pubkey, sig, msg } => {
                w.bytes(pubkey);
                w.bytes(sig);
                w.u32(msg.len());
                w.bytes(msg);
            }
        }
        w.finish()
    }

    /// The base64 text form of the blob.
    pub fn to_text(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD_NO_PAD.encode(self.encode().as_slice()))
    }

    /// Parses the base64 text form. Whitespace, padding and the URL-safe
    /// alphabet are tolerated.
    pub fn from_text(text: &str) -> Result<Blob, String> {
        let cleaned: Zeroizing<String> = Zeroizing::new(
            text.chars()
                .filter(|c| !c.is_whitespace() && *c != '=')
                .map(|c| match c {
                    '-' => '+',
                    '_' => '/',
                    other => other,
                })
                .collect(),
        );
        if cleaned.is_empty() {
            return Err("Nothing to import.".into());
        }
        let bytes = Zeroizing::new(
            STANDARD_NO_PAD
                .decode(cleaned.as_bytes())
                .map_err(|_| "This is not a FROST wallet message: invalid base64.".to_string())?,
        );
        Blob::decode(&bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Blob, String> {
        if bytes.len() < MAGIC.len() || bytes[..MAGIC.len()] != MAGIC {
            return Err("This is not a FROST wallet message.".into());
        }
        if bytes.len() < MAGIC.len() + 2 + 4 {
            return Err("The message is truncated.".into());
        }
        let (payload, checksum) = bytes.split_at(bytes.len() - 4);
        if Sha256::digest(payload)[..4] != *checksum {
            return Err(
                "Checksum mismatch: the message is damaged or incomplete. Transfer it again."
                    .into(),
            );
        }
        if payload[3] != VERSION {
            return Err(format!(
                "Unsupported message version {} (this wallet speaks version {VERSION}).",
                payload[3]
            ));
        }

        let mut r = Reader {
            bytes: &payload[5..],
        };
        let blob = match payload[4] {
            kind::HOST_SECRET => Blob::HostSecret(r.secret_scalar()?),
            kind::HOST_PUBLIC => Blob::HostPublic(r.point()?),
            kind::DKG_PARAMS => {
                let sid = r.sid()?;
                let t = r.u16()?;
                let n = r.count()?;
                Blob::DkgParams {
                    sid,
                    t,
                    hosts: r.points(n)?,
                }
            }
            kind::DKG_P1 => {
                let sid = r.sid()?;
                let idx = r.u16()?;
                let t = r.count()?;
                let n = r.count()?;
                Blob::DkgP1 {
                    sid,
                    idx,
                    msg: ParticipantMsg1 {
                        commitment: r.points(t)?,
                        pop: r.array()?,
                        pubnonce: r.point()?,
                        enc_shares: r.scalars(n)?,
                    },
                }
            }
            kind::DKG_C1 => {
                let sid = r.sid()?;
                let n = r.count()?;
                let k = r.count()?;
                Blob::DkgC1 {
                    sid,
                    msg: CoordinatorMsg1 {
                        coms_to_secrets: r.points(n)?,
                        sum_coms_to_nonconst_terms: r.points(k)?,
                        pops: r.sigs(n)?,
                        pubnonces: r.points(n)?,
                        enc_secshares: r.scalars(n)?,
                    },
                }
            }
            kind::DKG_P2 => Blob::DkgP2 {
                sid: r.sid()?,
                idx: r.u16()?,
                msg: ParticipantMsg2 { sig: r.array()? },
            },
            kind::DKG_C2 => {
                let sid = r.sid()?;
                let n = r.count()?;
                Blob::DkgC2 {
                    sid,
                    msg: CoordinatorMsg2 { cert: r.sigs(n)? },
                }
            }
            kind::RECOVERY => Blob::Recovery(decode_recovery(r.rest())?),
            kind::SHARE => {
                let idx = r.u16()?;
                let t = r.u16()?;
                let n = r.count()?;
                let secshare = r.secret_scalar()?;
                let threshold_pubkey = r.point()?;
                let pubshares = r.points(n)?;
                if t == 0 || t > n || idx >= n {
                    return Err("The key share backup is inconsistent.".into());
                }
                Blob::Share(DKGOutput {
                    idx,
                    t,
                    secshare: *secshare,
                    threshold_pubkey,
                    pubshares,
                })
            }
            kind::SIGN_REQUEST => {
                let ssid = r.sid()?;
                let group = r.point()?;
                let count = r.u8()?;
                if count > MAX_TWEAKS {
                    return Err("Too many tweaks.".into());
                }
                let mut tweaks = Vec::with_capacity(count);
                for _ in 0..count {
                    let is_xonly = match r.u8()? {
                        0 => false,
                        1 => true,
                        _ => return Err("Invalid tweak flag.".into()),
                    };
                    tweaks.push(Tweak {
                        value: r.array()?,
                        is_xonly,
                    });
                }
                Blob::SignRequest {
                    ssid,
                    group,
                    tweaks,
                    msg: r.message()?,
                }
            }
            kind::SIGN_NONCE => Blob::SignNonce {
                ssid: r.sid()?,
                idx: r.u16()?,
                nonce: r.pubnonce()?,
            },
            kind::SIGN_PACKAGE => {
                let ssid = r.sid()?;
                let count = r.count()?;
                let mut nonces = Vec::with_capacity(count);
                for _ in 0..count {
                    nonces.push((r.u16()?, r.pubnonce()?));
                }
                Blob::SignPackage { ssid, nonces }
            }
            kind::SIGN_PARTIAL => Blob::SignPartial {
                ssid: r.sid()?,
                idx: r.u16()?,
                psig: r.scalar()?,
            },
            kind::SIGNATURE => Blob::Signature {
                pubkey: r.array()?,
                sig: r.array()?,
                msg: r.message()?,
            },
            other => return Err(format!("Unknown message kind 0x{other:02x}.")),
        };
        r.end()?;
        Ok(blob)
    }

    fn kind(&self) -> u8 {
        match self {
            Blob::HostSecret(_) => kind::HOST_SECRET,
            Blob::HostPublic(_) => kind::HOST_PUBLIC,
            Blob::DkgParams { .. } => kind::DKG_PARAMS,
            Blob::DkgP1 { .. } => kind::DKG_P1,
            Blob::DkgC1 { .. } => kind::DKG_C1,
            Blob::DkgP2 { .. } => kind::DKG_P2,
            Blob::DkgC2 { .. } => kind::DKG_C2,
            Blob::Recovery(_) => kind::RECOVERY,
            Blob::Share(_) => kind::SHARE,
            Blob::SignRequest { .. } => kind::SIGN_REQUEST,
            Blob::SignNonce { .. } => kind::SIGN_NONCE,
            Blob::SignPackage { .. } => kind::SIGN_PACKAGE,
            Blob::SignPartial { .. } => kind::SIGN_PARTIAL,
            Blob::Signature { .. } => kind::SIGNATURE,
        }
    }
}

/// `transcript || cert`, as in the reference. The transcript starts with `t`
/// and the participant count follows from the total length.
fn decode_recovery(bytes: &[u8]) -> Result<RecoveryData, String> {
    const BAD: &str = "The recovery data is malformed.";
    if bytes.len() < 4 {
        return Err(BAD.into());
    }
    let t = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if t == 0 || t > MAX_PARTICIPANTS {
        return Err(BAD.into());
    }
    // Per participant: host pubkey, pubnonce, encrypted share, signature.
    let per_participant = POINT + POINT + SCALAR + SIG;
    let rest = bytes
        .len()
        .checked_sub(4 + POINT * t)
        .ok_or_else(|| BAD.to_string())?;
    if rest == 0 || rest % per_participant != 0 {
        return Err(BAD.into());
    }
    let n = rest / per_participant;
    if n > MAX_PARTICIPANTS || t > n {
        return Err(BAD.into());
    }
    let (transcript, cert) = bytes.split_at(bytes.len() - SIG * n);
    let transcript = CertEQTranscript::try_from((transcript, n)).map_err(|_| BAD.to_string())?;
    let mut r = Reader { bytes: cert };
    Ok(RecoveryData {
        transcript,
        cert: r.sigs(n)?,
    })
}

struct Writer {
    out: Zeroizing<Vec<u8>>,
}

impl Writer {
    fn new(kind: u8) -> Self {
        let mut out = Zeroizing::new(Vec::with_capacity(256));
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(kind);
        Self { out }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    // Lengths are bounded when the values are created, well below these
    // integer widths.
    fn u8(&mut self, v: usize) {
        self.out.push(v as u8);
    }

    fn u16(&mut self, v: usize) {
        self.bytes(&(v as u16).to_be_bytes());
    }

    fn u32(&mut self, v: usize) {
        self.bytes(&(v as u32).to_be_bytes());
    }

    fn point(&mut self, p: &ProjectivePoint) {
        self.bytes(&compress_default(p));
    }

    fn points(&mut self, points: &[ProjectivePoint]) {
        for p in points {
            self.point(p);
        }
    }

    fn scalar(&mut self, s: &Scalar) {
        self.bytes(&s.to_bytes());
    }

    fn secret_scalar(&mut self, s: &Scalar) {
        let bytes = Zeroizing::new(s.to_bytes());
        self.bytes(&bytes);
    }

    fn scalars(&mut self, scalars: &[Scalar]) {
        for s in scalars {
            self.scalar(s);
        }
    }

    fn finish(mut self) -> Zeroizing<Vec<u8>> {
        let checksum = Sha256::digest(self.out.as_slice());
        self.out.extend_from_slice(&checksum[..4]);
        self.out
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.bytes.len() < len {
            return Err("The message is truncated.".into());
        }
        let (head, tail) = self.bytes.split_at(len);
        self.bytes = tail;
        Ok(head)
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.bytes)
    }

    fn end(&self) -> Result<(), String> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err("The message has unexpected trailing data.".into())
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<usize, String> {
        Ok(self.take(1)?[0] as usize)
    }

    fn u16(&mut self) -> Result<usize, String> {
        Ok(u16::from_be_bytes(self.array()?) as usize)
    }

    /// A participant-sized element count.
    fn count(&mut self) -> Result<usize, String> {
        let count = self.u16()?;
        if count > MAX_PARTICIPANTS {
            return Err(format!(
                "The message describes more than {MAX_PARTICIPANTS} participants."
            ));
        }
        Ok(count)
    }

    fn sid(&mut self) -> Result<SessionId, String> {
        self.array()
    }

    fn message(&mut self) -> Result<Vec<u8>, String> {
        let len = u32::from_be_bytes(self.array()?) as usize;
        if len > MAX_MESSAGE_LEN {
            return Err("The message to sign is too large.".into());
        }
        Ok(self.take(len)?.to_vec())
    }

    fn point(&mut self) -> Result<ProjectivePoint, String> {
        decompress_default(&self.array()?)
            .ok_or_else(|| "The message contains an invalid curve point.".to_string())
    }

    fn points(&mut self, count: usize) -> Result<Vec<ProjectivePoint>, String> {
        (0..count).map(|_| self.point()).collect()
    }

    fn scalar(&mut self) -> Result<Scalar, String> {
        parse_scalar_from_bytes(self.array()?)
            .map_err(|_| "The message contains an invalid scalar.".to_string())
    }

    fn scalars(&mut self, count: usize) -> Result<Vec<Scalar>, String> {
        (0..count).map(|_| self.scalar()).collect()
    }

    fn secret_scalar(&mut self) -> Result<Zeroizing<Scalar>, String> {
        let bytes = Zeroizing::new(self.array()?);
        let scalar = Zeroizing::new(
            parse_secret_scalar_from_bytes(bytes)
                .map_err(|_| "The backup contains an invalid secret.".to_string())?,
        );
        if bool::from(scalar.is_zero()) {
            return Err("The backup contains an invalid secret.".into());
        }
        Ok(scalar)
    }

    fn sigs(&mut self, count: usize) -> Result<Vec<[u8; SIG]>, String> {
        (0..count).map(|_| self.array()).collect()
    }

    fn pubnonce(&mut self) -> Result<PubNonce, String> {
        Ok(PubNonce {
            R1: self.point()?,
            R2: self.point()?,
        })
    }
}
