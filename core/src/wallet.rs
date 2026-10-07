//! The wallet model: one in-memory session of either a participant or a
//! coordinator, driven by JSON requests.
//!
//! The page is a thin view over this module. It sends `{"op": ...}` requests
//! and renders the state snapshot that comes back with every response.
//! Everything that crosses the air gap goes through [`Wallet::import`], which
//! decodes the blob and routes it by kind and by where the session currently
//! is, so the user never has to say what a pasted string is.
//!
//! The ChillDKG and FROST drivers are consumed by a failed step, so every
//! check that can be made up front (session id, sender, round) is made before
//! a message is handed to a driver.

#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::wire::{Blob, MAX_MESSAGE_LEN, MAX_PARTICIPANTS, MAX_TWEAKS, SessionId};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chilldkg_rs::crypto::ec::{
    compress_default, compress_point_bip340, decompress_default, parse_secret_scalar_from_bytes,
};
use chilldkg_rs::crypto::tagged_hasher;
use chilldkg_rs::dkg::msg::{
    CoordinatorDKGOutput, DKGOutput, ParticipantMsg1, ParticipantMsg2, RecoveryData,
};
use chilldkg_rs::dkg::{self, ChillDkgError, ParticipantInitialState};
use chilldkg_rs::sign::{self, PubNonce, SignError, Tweak};
use k256::{ProjectivePoint, Scalar};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Domain separation of the hash that mixes user entropy into a host key.
const TAG_HOST_KEY: &str = "frost-wallet/host-key";
/// What dice and coins must add up to when a host key is made without device
/// randomness. The host public key is published in the recovery data, so a
/// guessable host key would give away the key share.
const MIN_USER_ENTROPY_BITS: usize = 128;

/// Source of randomness, supplied by the host environment.
pub type Rng = Box<dyn FnMut(&mut [u8])>;

type Res<T> = Result<T, String>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Participant,
    Coordinator,
}

pub struct Wallet {
    rng: Rng,
    role: Option<Role>,
    p: ParticipantSide,
    c: CoordinatorSide,
    /// Result of the last signature verification.
    verified: Option<Value>,
}

#[derive(Default)]
struct ParticipantSide {
    host: Option<Zeroizing<Scalar>>,
    dkg: Option<PDkg>,
    share: Option<DKGOutput>,
    recovery: Option<RecoveryData>,
    sign: Option<PSign>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Participant only: the request is shown and waits for approval.
    Review,
    Round1,
    Round2,
    Done,
    Failed,
}

impl Stage {
    fn name(self) -> &'static str {
        match self {
            Stage::Review => "review",
            Stage::Round1 => "round1",
            Stage::Round2 => "round2",
            Stage::Done => "done",
            Stage::Failed => "failed",
        }
    }

    /// A round is in flight and holds state that an import must not clobber.
    fn is_running(self) -> bool {
        matches!(self, Stage::Round1 | Stage::Round2)
    }
}

struct PDkg {
    sid: SessionId,
    t: usize,
    hosts: Vec<ProjectivePoint>,
    idx: usize,
    stage: Stage,
    driver: Option<dkg::Participant>,
    out: Option<Value>,
    error: Option<String>,
}

struct PSign {
    ssid: SessionId,
    msg: Vec<u8>,
    tweaks: Vec<Tweak>,
    signing_key: ProjectivePoint,
    stage: Stage,
    signer: Option<sign::Signer>,
    signers: Vec<usize>,
    out: Option<Value>,
    error: Option<String>,
}

#[derive(Default)]
struct CoordinatorSide {
    roster: Vec<ProjectivePoint>,
    dkg: Option<CDkg>,
    group: Option<CoordinatorDKGOutput>,
    recovery: Option<RecoveryData>,
    sign: Option<CSign>,
}

struct CDkg {
    sid: SessionId,
    t: usize,
    hosts: Vec<ProjectivePoint>,
    stage: Stage,
    driver: dkg::Coordinator,
    params: Value,
    msgs1: Vec<Option<ParticipantMsg1>>,
    out1: Option<Value>,
    msgs2: Vec<Option<ParticipantMsg2>>,
    out2: Option<Value>,
    error: Option<String>,
}

struct CSign {
    ssid: SessionId,
    msg: Vec<u8>,
    tweaks: Vec<Tweak>,
    signing_key: ProjectivePoint,
    stage: Stage,
    driver: sign::Coordinator,
    request: Value,
    nonces: BTreeMap<usize, PubNonce>,
    package: Option<Value>,
    signers: Vec<usize>,
    partials: BTreeMap<usize, Scalar>,
    signature: Option<Value>,
    error: Option<String>,
}

/// What an import did, for the page to report and navigate on.
struct Imported {
    message: String,
    tab: &'static str,
    /// More messages of the same kind are expected; keep the import sheet open.
    more: bool,
}

impl Imported {
    fn new(tab: &'static str, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            tab,
            more: false,
        }
    }

    fn more(mut self, more: bool) -> Self {
        self.more = more;
        self
    }
}

impl Wallet {
    pub fn new(rng: Rng) -> Self {
        Self {
            rng,
            role: None,
            p: ParticipantSide::default(),
            c: CoordinatorSide::default(),
            verified: None,
        }
    }

    /// Handles one JSON request and returns the JSON response. The response
    /// always carries the current state snapshot.
    pub fn handle(&mut self, request: &str) -> String {
        let result = serde_json::from_str::<Value>(request)
            .map_err(|_| "Malformed request.".to_string())
            .and_then(|req| self.dispatch(&req));
        let response = match result {
            Ok(result) => json!({ "ok": true, "result": result, "state": self.state() }),
            Err(error) => json!({ "ok": false, "error": error, "state": self.state() }),
        };
        response.to_string()
    }

    fn dispatch(&mut self, req: &Value) -> Res<Value> {
        let op = req["op"].as_str().unwrap_or_default();
        match op {
            "state" => Ok(Value::Null),
            "set_role" => {
                let role = match req["role"].as_str() {
                    Some("participant") => Role::Participant,
                    Some("coordinator") => Role::Coordinator,
                    _ => return Err("Unknown role.".into()),
                };
                self.reset();
                self.role = Some(role);
                Ok(Value::Null)
            }
            "reset" => {
                self.reset();
                Ok(Value::Null)
            }
            "import" => {
                let blob = Blob::from_text(str_field(req, "data")?)?;
                let done = self.import(blob)?;
                Ok(json!({ "message": done.message, "tab": done.tab, "more": done.more }))
            }
            "verify" => {
                let pubkey = xonly_key(str_field(req, "pubkey")?).ok_or(
                    "The public key must be 32 bytes of hex (x-only) or 33 bytes (compressed).",
                )?;
                let sig: [u8; 64] = hex_array(str_field(req, "sig")?)
                    .map_err(|_| "The signature must be 64 bytes of hex.".to_string())?;
                let msg = unhex(str_field(req, "msg")?)
                    .map_err(|_| "The message is not valid hex.".to_string())?;
                self.verify(pubkey, sig, msg)?;
                Ok(Value::Null)
            }
            "clear_verify" => {
                self.verified = None;
                Ok(Value::Null)
            }
            _ => match self.role {
                Some(Role::Participant) => self.participant_op(op, req),
                Some(Role::Coordinator) => self.coordinator_op(op, req),
                None => Err("Choose a role first.".into()),
            },
        }
    }

    fn reset(&mut self) {
        self.role = None;
        self.p = ParticipantSide::default();
        self.c = CoordinatorSide::default();
        self.verified = None;
    }

    fn import(&mut self, blob: Blob) -> Res<Imported> {
        if let Blob::Signature { pubkey, sig, msg } = blob {
            let valid = self.verify(pubkey, sig, msg)?;
            return Ok(Imported::new(
                "verify",
                if valid {
                    "Signature is valid."
                } else {
                    "Signature is NOT valid."
                },
            ));
        }
        match self.role {
            Some(Role::Participant) => self.participant_import(blob),
            Some(Role::Coordinator) => self.coordinator_import(blob),
            None => Err("Choose a role first.".into()),
        }
    }

    fn verify(&mut self, pubkey: [u8; 32], sig: [u8; 64], msg: Vec<u8>) -> Res<bool> {
        let Q = lift_x(&pubkey).ok_or("The public key is not a valid x-only key.")?;
        let valid = sign::verify(&Q, sig, &signed_digest(&msg), &[]).is_ok();
        let group = match self.role {
            Some(Role::Participant) => self.p.share.as_ref().map(|s| s.threshold_pubkey),
            Some(Role::Coordinator) => self.c.group.as_ref().map(|g| g.threshold_pubkey),
            None => None,
        };
        self.verified = Some(json!({
            "valid": valid,
            "pubkey": hex(&pubkey),
            "sig": hex(&sig),
            "msg": msg_json(&msg),
            "ours": group.is_some_and(|g| compress_point_bip340(&g) == pubkey),
        }));
        Ok(valid)
    }

    // ---------------------------------------------------------------- participant

    fn participant_op(&mut self, op: &str, req: &Value) -> Res<Value> {
        let p = &mut self.p;
        match op {
            "p_new_host" => {
                if p.host.is_some() {
                    return Err("A host key is already loaded.".into());
                }
                let device = req["device"].as_bool().unwrap_or(true);
                let dice = Zeroizing::new(req["dice"].as_str().unwrap_or_default().to_string());
                let coins = Zeroizing::new(req["coins"].as_str().unwrap_or_default().to_string());
                // The drawing: x, y and time of every point, one after another.
                let drawing: Zeroizing<Vec<f64>> = Zeroizing::new(
                    req["drawing"]
                        .as_array()
                        .map(Vec::as_slice)
                        .unwrap_or_default()
                        .iter()
                        .map(|v| v.as_f64().filter(|f| f.is_finite()))
                        .collect::<Option<_>>()
                        .filter(|points: &Vec<f64>| points.len().is_multiple_of(3))
                        .ok_or("Malformed drawing data.")?,
                );
                if !dice.bytes().all(|b| (b'1'..=b'6').contains(&b))
                    || !coins.bytes().all(|b| b == b'H' || b == b'T')
                {
                    return Err("Malformed dice rolls or coin flips.".into());
                }
                // A roll is worth log2(6) = 2.58 bits, a flip one. A drawing
                // cannot be measured, so it counts for nothing.
                let bits = dice.len() * 2584 / 1000 + coins.len();
                if !device && bits < MIN_USER_ENTROPY_BITS {
                    return Err(format!(
                        "Without this device's randomness the key rests on your dice and coins alone, and they must add up to {MIN_USER_ENTROPY_BITS} bits: you have {bits}. That takes 50 rolls, {MIN_USER_ENTROPY_BITS} flips, or a mix; a drawing does not count."
                    ));
                }
                let drawing: Zeroizing<Vec<u8>> =
                    Zeroizing::new(drawing.iter().flat_map(|v| v.to_be_bytes()).collect());
                let rng = device.then_some(&mut self.rng);
                p.host = Some(host_scalar(
                    rng,
                    dice.as_bytes(),
                    coins.as_bytes(),
                    &drawing,
                ));
            }
            "p_forget_host" => {
                if p.dkg.as_ref().is_some_and(|d| d.stage.is_running()) {
                    return Err("A key generation session is in progress. Abort it first.".into());
                }
                p.host = None;
                p.dkg = None;
            }
            "p_forget_share" => {
                p.share = None;
                p.recovery = None;
                p.sign = None;
                if p.dkg.as_ref().is_some_and(|d| !d.stage.is_running()) {
                    p.dkg = None;
                }
            }
            "p_dkg_join" => {
                let host = p.host.as_ref().ok_or("No host key loaded.")?;
                let session = p
                    .dkg
                    .as_mut()
                    .filter(|d| d.stage == Stage::Review)
                    .ok_or("There is no key generation session waiting for approval.")?;
                let mut driver = dkg::Participant::new_with_secret(host).map_err(dkg_error)?;
                let random = random_bytes(&mut self.rng);
                match driver.step1((session.hosts.clone(), session.t, *random)) {
                    Ok(msg) => {
                        session.out = Some(out(
                            &Blob::DkgP1 {
                                sid: session.sid,
                                idx: session.idx,
                                msg,
                            },
                            format!(
                                "frost-keygen-{}-round1-p{}",
                                short(&session.sid),
                                session.idx + 1
                            ),
                        ));
                        session.driver = Some(driver);
                        session.stage = Stage::Round1;
                    }
                    Err(e) => return Err(session.fail(dkg_error(e))),
                }
            }
            "p_dkg_abort" => p.dkg = None,
            "p_sign_approve" => {
                let share = p.share.as_ref().ok_or("No key share loaded.")?;
                let session = p
                    .sign
                    .as_mut()
                    .filter(|s| s.stage == Stage::Review)
                    .ok_or("There is no signing request waiting for approval.")?;
                let mut signer = sign::Signer::new(share);
                let random = random_bytes(&mut self.rng);
                match signer.step1((
                    Some(signed_digest(&session.msg)),
                    Some(session.tweaks.clone()),
                    *random,
                )) {
                    Ok((idx, nonce)) => {
                        session.out = Some(out(
                            &Blob::SignNonce {
                                ssid: session.ssid,
                                idx,
                                nonce,
                            },
                            format!("frost-sign-{}-nonce-p{}", short(&session.ssid), idx + 1),
                        ));
                        session.signer = Some(signer);
                        session.stage = Stage::Round1;
                    }
                    Err(e) => return Err(session.fail(sign_error(e))),
                }
            }
            "p_sign_abort" => p.sign = None,
            "export" => {
                return match req["what"].as_str() {
                    Some("host_secret") => {
                        let host = p.host.as_ref().ok_or("No host key loaded.")?;
                        let name = format!("frost-host-SECRET-{}", fingerprint(&host_pubkey(host)));
                        Ok(out(&Blob::HostSecret(host.clone()), name))
                    }
                    Some("share") => {
                        let share = p.share.as_ref().ok_or("No key share loaded.")?;
                        let name = format!(
                            "frost-share-SECRET-{}-p{}",
                            fingerprint(&share.threshold_pubkey),
                            share.idx + 1
                        );
                        Ok(out(&Blob::Share(share.clone()), name))
                    }
                    _ => Err("Unknown export.".into()),
                };
            }
            _ => return Err(format!("Unknown operation '{op}'.")),
        }
        Ok(Value::Null)
    }

    fn participant_import(&mut self, blob: Blob) -> Res<Imported> {
        let p = &mut self.p;
        match blob {
            Blob::HostSecret(secret) => {
                if let Some(host) = &p.host {
                    return if **host == *secret {
                        Ok(Imported::new(
                            "identity",
                            "This host key is already loaded.",
                        ))
                    } else {
                        Err("A different host key is already loaded. Forget it first on the Identity tab.".into())
                    };
                }
                p.host = Some(secret);
                Ok(Imported::new("identity", "Host secret key restored."))
            }
            Blob::DkgParams { sid, t, hosts } => {
                let host = p
                    .host
                    .as_ref()
                    .ok_or("Create or restore your host key first (Identity tab).")?;
                if p.share.is_some() {
                    return Err("A key share is already loaded. Forget it on the Backup tab before generating a new key.".into());
                }
                if let Some(current) = &p.dkg
                    && current.stage.is_running()
                {
                    return Err(if current.sid == sid {
                        "You have already joined this key generation session.".into()
                    } else {
                        "Another key generation session is in progress. Abort it first.".to_string()
                    });
                }
                ParticipantInitialState::validate_public_session_params(&hosts, t)
                    .map_err(dkg_error)?;
                let me = host_pubkey(host);
                let idx = hosts.iter().position(|P| *P == me).ok_or(
                    "Your host public key is not part of this session. Send your host public key to the coordinator and ask for new parameters.",
                )?;
                let message = format!(
                    "Key generation session: {t}-of-{}. You are participant #{}. Review and join.",
                    hosts.len(),
                    idx + 1
                );
                p.dkg = Some(PDkg {
                    sid,
                    t,
                    hosts,
                    idx,
                    stage: Stage::Review,
                    driver: None,
                    out: None,
                    error: None,
                });
                Ok(Imported::new("keygen", message))
            }
            Blob::DkgC1 { sid, msg } => {
                let session = p.dkg.as_mut().filter(|d| d.sid == sid).ok_or(
                    "This message belongs to a key generation session you have not joined.",
                )?;
                match session.stage {
                    Stage::Round1 => {}
                    Stage::Review => {
                        return Err("Join the key generation session before importing the coordinator's reply.".into());
                    }
                    _ => return Err("This round 1 message has already been processed.".into()),
                }
                let driver = session.driver.as_mut().ok_or("Session state is missing.")?;
                let aux = random_bytes(&mut self.rng);
                match driver.step2((msg, *aux)) {
                    Ok(msg) => {
                        session.out = Some(out(
                            &Blob::DkgP2 {
                                sid,
                                idx: session.idx,
                                msg,
                            },
                            format!("frost-keygen-{}-round2-p{}", short(&sid), session.idx + 1),
                        ));
                        session.stage = Stage::Round2;
                        Ok(Imported::new(
                            "keygen",
                            "Round 1 verified. Send your round 2 message to the coordinator.",
                        ))
                    }
                    Err(e) => Err(session.fail(dkg_error(e))),
                }
            }
            Blob::DkgC2 { sid, msg } => {
                let session = p.dkg.as_mut().filter(|d| d.sid == sid).ok_or(
                    "This certificate belongs to a key generation session you have not joined.",
                )?;
                match session.stage {
                    Stage::Round2 => {}
                    Stage::Done => {
                        return Err("This certificate has already been processed.".into());
                    }
                    _ => {
                        return Err("It is too early for the certificate: import the coordinator's round 1 message first.".into());
                    }
                }
                let driver = session.driver.as_mut().ok_or("Session state is missing.")?;
                match driver.finalize(msg) {
                    Ok((output, recovery)) => {
                        p.share = Some(output);
                        p.recovery = Some(recovery);
                        session.driver = None;
                        session.out = None;
                        session.stage = Stage::Done;
                        Ok(Imported::new(
                            "keygen",
                            "Key generation complete. Back up your key share now.",
                        ))
                    }
                    Err(e) => Err(session.fail(dkg_error(e))),
                }
            }
            Blob::Recovery(recovery) => {
                if p.dkg.as_ref().is_some_and(|d| d.stage.is_running()) {
                    return Err("A key generation session is in progress. Abort it first.".into());
                }
                let public = dkg::Coordinator::recover(&recovery).map_err(dkg_error)?;
                if let Some(share) = &p.share {
                    if share.threshold_pubkey != public.threshold_pubkey
                        || share.pubshares != public.pubshares
                        || share.t != public.t
                    {
                        return Err("This recovery data belongs to a different key than the loaded share. Forget the share first on the Backup tab.".into());
                    }
                    p.recovery = Some(recovery);
                    return Ok(Imported::new(
                        "backup",
                        "Recovery data matches the loaded key share and was attached.",
                    ));
                }
                let host = p.host.as_ref().ok_or(
                    "Restore your host secret key first: it is needed to recover the key share from recovery data.",
                )?;
                let share = dkg::Participant::recover(host, &recovery).map_err(dkg_error)?;
                let message = format!(
                    "Key share recovered: you are participant #{} of a {}-of-{} key.",
                    share.idx + 1,
                    share.t,
                    share.pubshares.len()
                );
                p.share = Some(share);
                p.recovery = Some(recovery);
                p.dkg = None;
                Ok(Imported::new("backup", message))
            }
            Blob::Share(share) => {
                if let Some(current) = &p.share {
                    return if *current == share {
                        Ok(Imported::new("backup", "This key share is already loaded."))
                    } else {
                        Err("A different key share is already loaded. Forget it first on the Backup tab.".into())
                    };
                }
                if p.dkg.as_ref().is_some_and(|d| d.stage.is_running()) {
                    return Err("A key generation session is in progress. Abort it first.".into());
                }
                let ids: Vec<usize> = (0..share.pubshares.len()).collect();
                if ProjectivePoint::GENERATOR * share.secshare != share.pubshares[share.idx]
                    || sign::validate_signers(
                        share.t,
                        &share.pubshares,
                        &share.threshold_pubkey,
                        &ids,
                    )
                    .is_err()
                {
                    return Err("The key share backup is inconsistent and was rejected.".into());
                }
                let message = format!(
                    "Key share restored: you are participant #{} of a {}-of-{} key.",
                    share.idx + 1,
                    share.t,
                    share.pubshares.len()
                );
                p.share = Some(share);
                p.recovery = None;
                p.dkg = None;
                Ok(Imported::new("backup", message))
            }
            Blob::SignRequest {
                ssid,
                group,
                msg,
                tweaks,
            } => {
                let share = p
                    .share
                    .as_ref()
                    .ok_or("No key share loaded. Generate a key or restore a backup first.")?;
                if group != share.threshold_pubkey {
                    return Err("This signing request is for a different group key.".into());
                }
                if let Some(current) = &p.sign {
                    if current.ssid == ssid && current.stage != Stage::Failed {
                        return Err("This signing request has already been imported.".into());
                    }
                    if current.stage == Stage::Round1 {
                        return Err("Another signing session is waiting for its signing package. Abort it first.".into());
                    }
                }
                let signing_key =
                    sign::signing_pubkey(&share.threshold_pubkey, &tweaks).map_err(sign_error)?;
                p.sign = Some(PSign {
                    ssid,
                    msg,
                    tweaks,
                    signing_key,
                    stage: Stage::Review,
                    signer: None,
                    signers: Vec::new(),
                    out: None,
                    error: None,
                });
                Ok(Imported::new(
                    "sign",
                    "Signing request received. Review the message before approving.",
                ))
            }
            Blob::SignPackage { ssid, nonces } => {
                let share = p.share.as_ref().ok_or("No key share loaded.")?;
                let session =
                    p.sign.as_mut().filter(|s| s.ssid == ssid).ok_or(
                        "This signing package belongs to a session you have not approved.",
                    )?;
                match session.stage {
                    Stage::Round1 => {}
                    Stage::Review => {
                        return Err("Approve the signing request and send your nonce first.".into());
                    }
                    _ => return Err("This signing package has already been processed.".into()),
                }
                if !nonces.iter().any(|(idx, _)| *idx == share.idx) {
                    return Err("You are not part of the signing set of this package. The coordinator proceeded without your nonce; abort this session.".into());
                }
                let signer = session.signer.as_mut().ok_or("Session state is missing.")?;
                let signers = nonces.iter().map(|(idx, _)| *idx).collect();
                match signer.finalize((nonces, signed_digest(&session.msg), session.tweaks.clone()))
                {
                    Ok((idx, psig)) => {
                        session.out = Some(out(
                            &Blob::SignPartial { ssid, idx, psig },
                            format!("frost-sign-{}-partial-p{}", short(&ssid), idx + 1),
                        ));
                        session.signer = None;
                        session.signers = signers;
                        session.stage = Stage::Done;
                        Ok(Imported::new(
                            "sign",
                            "Partial signature created. Send it to the coordinator.",
                        ))
                    }
                    Err(e) => Err(session.fail(sign_error(e))),
                }
            }
            Blob::HostPublic(_) => Err(
                "This is a host public key. It goes to the coordinator, not to a participant."
                    .into(),
            ),
            other @ (Blob::DkgP1 { .. }
            | Blob::DkgP2 { .. }
            | Blob::SignNonce { .. }
            | Blob::SignPartial { .. }) => Err(format!(
                "This is a {}. It goes to the coordinator, not to a participant.",
                other.title()
            )),
            Blob::Signature { .. } => unreachable!("handled by import"),
        }
    }

    // ---------------------------------------------------------------- coordinator

    fn coordinator_op(&mut self, op: &str, req: &Value) -> Res<Value> {
        let c = &mut self.c;
        match op {
            "c_roster_remove" => {
                if c.dkg.as_ref().is_some_and(|d| d.stage.is_running()) {
                    return Err("A key generation session is in progress. Abort it first.".into());
                }
                let index = req["index"].as_u64().unwrap_or(u64::MAX) as usize;
                if index >= c.roster.len() {
                    return Err("No such participant.".into());
                }
                c.roster.remove(index);
            }
            "c_dkg_start" => {
                if c.dkg.as_ref().is_some_and(|d| d.stage.is_running()) {
                    return Err("A key generation session is already in progress.".into());
                }
                if c.group.is_some() {
                    return Err("A group key is already loaded. Forget it on the Backup tab before generating a new one.".into());
                }
                let t = req["t"].as_u64().unwrap_or(0) as usize;
                let hosts = c.roster.clone();
                if hosts.len() > MAX_PARTICIPANTS {
                    return Err(format!(
                        "At most {MAX_PARTICIPANTS} participants are supported."
                    ));
                }
                let driver = dkg::Coordinator::new(hosts.clone(), t).map_err(dkg_error)?;
                let mut sid = SessionId::default();
                (self.rng)(&mut sid);
                let n = hosts.len();
                c.dkg = Some(CDkg {
                    sid,
                    t,
                    stage: Stage::Round1,
                    driver,
                    params: out(
                        &Blob::DkgParams {
                            sid,
                            t,
                            hosts: hosts.clone(),
                        },
                        format!("frost-keygen-{}-params", short(&sid)),
                    ),
                    hosts,
                    msgs1: vec![None; n],
                    out1: None,
                    msgs2: vec![None; n],
                    out2: None,
                    error: None,
                });
            }
            "c_dkg_abort" => c.dkg = None,
            "c_forget_group" => {
                c.group = None;
                c.recovery = None;
                c.sign = None;
                if c.dkg.as_ref().is_some_and(|d| !d.stage.is_running()) {
                    c.dkg = None;
                }
            }
            "c_sign_start" => {
                let group = c.group.as_ref().ok_or(
                    "No group key loaded. Run key generation or restore recovery data first.",
                )?;
                if c.sign.as_ref().is_some_and(|s| s.stage.is_running()) {
                    return Err("A signing session is already in progress.".into());
                }
                let msg = unhex(str_field(req, "msg")?)
                    .map_err(|_| "The message is not valid hex.".to_string())?;
                if msg.len() > MAX_MESSAGE_LEN {
                    return Err(format!(
                        "The message is too large: at most {} KiB can be passed around.",
                        MAX_MESSAGE_LEN / 1024
                    ));
                }
                let mut tweaks = Vec::new();
                for tweak in req["tweaks"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
                    let value = hex_array(tweak["value"].as_str().unwrap_or_default())
                        .map_err(|_| "A tweak must be 32 bytes of hex.".to_string())?;
                    tweaks.push(Tweak {
                        value,
                        is_xonly: tweak["xonly"].as_bool().unwrap_or(false),
                    });
                }
                if tweaks.len() > MAX_TWEAKS {
                    return Err(format!("At most {MAX_TWEAKS} tweaks are supported."));
                }
                let signing_key =
                    sign::signing_pubkey(&group.threshold_pubkey, &tweaks).map_err(sign_error)?;
                let mut ssid = SessionId::default();
                (self.rng)(&mut ssid);
                c.sign = Some(CSign {
                    ssid,
                    stage: Stage::Round1,
                    driver: sign::Coordinator::new(group),
                    request: out(
                        &Blob::SignRequest {
                            ssid,
                            group: group.threshold_pubkey,
                            msg: msg.clone(),
                            tweaks: tweaks.clone(),
                        },
                        format!("frost-sign-{}-request", short(&ssid)),
                    ),
                    msg,
                    tweaks,
                    signing_key,
                    nonces: BTreeMap::new(),
                    package: None,
                    signers: Vec::new(),
                    partials: BTreeMap::new(),
                    signature: None,
                    error: None,
                });
            }
            "c_sign_package" => {
                let session = c
                    .sign
                    .as_mut()
                    .filter(|s| s.stage == Stage::Round1)
                    .ok_or("There is no signing session collecting nonces.")?;
                let t = c.group.as_ref().map_or(usize::MAX, |g| g.t);
                if session.nonces.len() < t {
                    return Err(format!(
                        "Not enough nonces yet: {} of {t} needed.",
                        session.nonces.len()
                    ));
                }
                let nonces: Vec<(usize, PubNonce)> = session
                    .nonces
                    .iter()
                    .map(|(idx, nonce)| (*idx, nonce.clone()))
                    .collect();
                match session.driver.step1(nonces) {
                    Ok(nonces) => {
                        session.signers = nonces.iter().map(|(idx, _)| *idx).collect();
                        session.package = Some(out(
                            &Blob::SignPackage {
                                ssid: session.ssid,
                                nonces,
                            },
                            format!("frost-sign-{}-package", short(&session.ssid)),
                        ));
                        session.stage = Stage::Round2;
                    }
                    Err(e) => return Err(session.fail(sign_error(e))),
                }
            }
            "c_sign_abort" => c.sign = None,
            _ => return Err(format!("Unknown operation '{op}'.")),
        }
        Ok(Value::Null)
    }

    fn coordinator_import(&mut self, blob: Blob) -> Res<Imported> {
        let c = &mut self.c;
        match blob {
            Blob::HostPublic(P) => {
                if c.dkg.as_ref().is_some_and(|d| d.stage.is_running()) {
                    return Err(
                        "A key generation session is in progress; its participants are fixed."
                            .into(),
                    );
                }
                if c.roster.contains(&P) {
                    return Err("This participant is already on the list.".into());
                }
                if c.roster.len() >= MAX_PARTICIPANTS {
                    return Err(format!(
                        "At most {MAX_PARTICIPANTS} participants are supported."
                    ));
                }
                c.roster.push(P);
                Ok(Imported::new(
                    "keygen",
                    format!(
                        "Participant #{} added ({}).",
                        c.roster.len(),
                        fingerprint(&P)
                    ),
                )
                .more(true))
            }
            Blob::DkgP1 { sid, idx, msg } => {
                let session = c
                    .dkg
                    .as_mut()
                    .filter(|d| d.sid == sid)
                    .ok_or("This message belongs to a different key generation session.")?;
                if session.stage != Stage::Round1 {
                    return Err("Round 1 is already closed.".into());
                }
                let slot = session
                    .msgs1
                    .get_mut(idx)
                    .ok_or("The message names a participant that is not in this session.")?;
                let replaced = slot.replace(msg).is_some();
                let got = session.msgs1.iter().flatten().count();
                let n = session.hosts.len();
                if got < n {
                    return Ok(Imported::new(
                        "keygen",
                        format!(
                            "Round 1 message from participant #{} {} ({got}/{n}).",
                            idx + 1,
                            if replaced { "replaced" } else { "received" }
                        ),
                    )
                    .more(true));
                }
                let msgs = session.msgs1.iter().flatten().cloned().collect();
                match session.driver.step1(msgs) {
                    Ok(msg) => {
                        session.out1 = Some(out(
                            &Blob::DkgC1 { sid, msg },
                            format!("frost-keygen-{}-round1-coordinator", short(&sid)),
                        ));
                        session.stage = Stage::Round2;
                        Ok(Imported::new(
                            "keygen",
                            "All round 1 messages received. Send the combined message to every participant.",
                        ))
                    }
                    Err(e) => Err(session.fail(dkg_error(e))),
                }
            }
            Blob::DkgP2 { sid, idx, msg } => {
                let session = c
                    .dkg
                    .as_mut()
                    .filter(|d| d.sid == sid)
                    .ok_or("This message belongs to a different key generation session.")?;
                match session.stage {
                    Stage::Round2 => {}
                    Stage::Round1 => {
                        return Err(
                            "Round 1 is not finished yet: round 1 messages are still missing."
                                .into(),
                        );
                    }
                    _ => return Err("Round 2 is already closed.".into()),
                }
                let slot = session
                    .msgs2
                    .get_mut(idx)
                    .ok_or("The message names a participant that is not in this session.")?;
                let replaced = slot.replace(msg).is_some();
                let got = session.msgs2.iter().flatten().count();
                let n = session.hosts.len();
                if got < n {
                    return Ok(Imported::new(
                        "keygen",
                        format!(
                            "Round 2 message from participant #{} {} ({got}/{n}).",
                            idx + 1,
                            if replaced { "replaced" } else { "received" }
                        ),
                    )
                    .more(true));
                }
                let msgs = session.msgs2.iter().flatten().cloned().collect();
                match session.driver.step2(msgs) {
                    Ok((msg, output, recovery)) => {
                        session.out2 = Some(out(
                            &Blob::DkgC2 { sid, msg },
                            format!("frost-keygen-{}-certificate", short(&sid)),
                        ));
                        session.stage = Stage::Done;
                        c.group = Some(output);
                        c.recovery = Some(recovery);
                        Ok(Imported::new(
                            "keygen",
                            "Key generation complete. Send the certificate to every participant.",
                        ))
                    }
                    Err(e) => Err(session.fail(dkg_error(e))),
                }
            }
            Blob::Recovery(recovery) => {
                if c.dkg.as_ref().is_some_and(|d| d.stage.is_running()) {
                    return Err("A key generation session is in progress. Abort it first.".into());
                }
                let group = dkg::Coordinator::recover(&recovery).map_err(dkg_error)?;
                if let Some(current) = &c.group {
                    return if *current == group {
                        Ok(Imported::new("backup", "This group key is already loaded."))
                    } else {
                        Err("A different group key is already loaded. Forget it first on the Backup tab.".into())
                    };
                }
                let message = format!(
                    "Group key restored: {}-of-{}.",
                    group.t,
                    group.pubshares.len()
                );
                c.group = Some(group);
                c.recovery = Some(recovery);
                c.dkg = None;
                Ok(Imported::new("backup", message))
            }
            Blob::SignNonce { ssid, idx, nonce } => {
                let session = c
                    .sign
                    .as_mut()
                    .filter(|s| s.ssid == ssid)
                    .ok_or("This nonce belongs to a different signing session.")?;
                if session.stage != Stage::Round1 {
                    return Err(
                        "The signing set is already fixed; this nonce arrived too late.".into(),
                    );
                }
                let group = c.group.as_ref().ok_or("No group key loaded.")?;
                if idx >= group.pubshares.len() {
                    return Err("The nonce names a participant that is not in this group.".into());
                }
                let replaced = session.nonces.insert(idx, nonce).is_some();
                let got = session.nonces.len();
                Ok(Imported::new(
                    "sign",
                    format!(
                        "Nonce from participant #{} {} ({got} of {} needed).",
                        idx + 1,
                        if replaced { "replaced" } else { "received" },
                        group.t
                    ),
                )
                .more(true))
            }
            Blob::SignPartial { ssid, idx, psig } => {
                let session = c
                    .sign
                    .as_mut()
                    .filter(|s| s.ssid == ssid)
                    .ok_or("This partial signature belongs to a different signing session.")?;
                match session.stage {
                    Stage::Round2 => {}
                    Stage::Round1 => {
                        return Err("Build and send the signing package before collecting partial signatures.".into());
                    }
                    _ => return Err("This signing session is already closed.".into()),
                }
                if !session.signers.contains(&idx) {
                    return Err(format!(
                        "Participant #{} is not part of this signing set.",
                        idx + 1
                    ));
                }
                let replaced = session.partials.insert(idx, psig).is_some();
                let got = session.partials.len();
                let need = session.signers.len();
                if got < need {
                    return Ok(Imported::new(
                        "sign",
                        format!(
                            "Partial signature from participant #{} {} ({got}/{need}).",
                            idx + 1,
                            if replaced { "replaced" } else { "received" }
                        ),
                    )
                    .more(true));
                }
                let psigs = session.partials.iter().map(|(i, s)| (*i, *s)).collect();
                match session.driver.step2((
                    psigs,
                    signed_digest(&session.msg),
                    session.tweaks.clone(),
                )) {
                    Ok(sig) => {
                        let pubkey = compress_point_bip340(&session.signing_key);
                        let blob = out(
                            &Blob::Signature {
                                pubkey,
                                sig,
                                msg: session.msg.clone(),
                            },
                            format!("frost-signature-{}", short(&ssid)),
                        );
                        session.signature = Some(json!({
                            "sig": hex(&sig),
                            "pubkey": hex(&pubkey),
                            "out": blob,
                        }));
                        session.stage = Stage::Done;
                        Ok(Imported::new("sign", "Signature complete and verified."))
                    }
                    Err(e) => Err(session.fail(sign_error(e))),
                }
            }
            other @ (Blob::HostSecret(_) | Blob::Share(_)) => Err(format!(
                "This is a SECRET {}. Never give it to a coordinator: it belongs only on its owner's participant device.",
                other.title()
            )),
            other @ (Blob::DkgParams { .. }
            | Blob::DkgC1 { .. }
            | Blob::DkgC2 { .. }
            | Blob::SignRequest { .. }
            | Blob::SignPackage { .. }) => Err(format!(
                "This is a {}. It goes to the participants, not to the coordinator.",
                other.title()
            )),
            Blob::Signature { .. } => unreachable!("handled by import"),
        }
    }

    // ---------------------------------------------------------------- snapshot

    /// The public view of the session, rendered by the page. Never contains
    /// secret key material: secrets leave only through an explicit `export`.
    pub fn state(&self) -> Value {
        match self.role {
            None => json!({ "role": null, "verified": self.verified }),
            Some(Role::Participant) => {
                let p = &self.p;
                json!({
                    "role": "participant",
                    "verified": self.verified,
                    "host": p.host.as_ref().map(|s| {
                        let P = host_pubkey(s);
                        let mut host = host_json(&P);
                        host["out"] = out(
                            &Blob::HostPublic(P),
                            format!("frost-host-pubkey-{}", fingerprint(&P)),
                        );
                        host
                    }),
                    "dkg": p.dkg.as_ref().map(|d| json!({
                        "sid": hex(&d.sid),
                        "t": d.t,
                        "n": d.hosts.len(),
                        "idx": d.idx,
                        "hosts": d.hosts.iter().map(host_json).collect::<Vec<_>>(),
                        "stage": d.stage.name(),
                        "out": d.out,
                        "error": d.error,
                    })),
                    "group": p.share.as_ref().map(|s| {
                        let mut group = group_json(s.t, &s.threshold_pubkey, &s.pubshares);
                        group["idx"] = json!(s.idx);
                        group["recovery"] = recovery_json(&p.recovery, &s.threshold_pubkey);
                        group
                    }),
                    "sign": p.sign.as_ref().map(|s| json!({
                        "ssid": hex(&s.ssid),
                        "stage": s.stage.name(),
                        "msg": msg_json(&s.msg),
                        "tweaks": tweaks_json(&s.tweaks),
                        "key": hex(&compress_point_bip340(&s.signing_key)),
                        "signers": s.signers,
                        "out": s.out,
                        "error": s.error,
                    })),
                })
            }
            Some(Role::Coordinator) => {
                let c = &self.c;
                json!({
                    "role": "coordinator",
                    "verified": self.verified,
                    "roster": c.roster.iter().map(host_json).collect::<Vec<_>>(),
                    "dkg": c.dkg.as_ref().map(|d| json!({
                        "sid": hex(&d.sid),
                        "t": d.t,
                        "n": d.hosts.len(),
                        "hosts": d.hosts.iter().map(host_json).collect::<Vec<_>>(),
                        "stage": d.stage.name(),
                        "params": d.params,
                        "got1": d.msgs1.iter().map(Option::is_some).collect::<Vec<_>>(),
                        "out1": d.out1,
                        "got2": d.msgs2.iter().map(Option::is_some).collect::<Vec<_>>(),
                        "out2": d.out2,
                        "error": d.error,
                    })),
                    "group": c.group.as_ref().map(|g| {
                        let mut group = group_json(g.t, &g.threshold_pubkey, &g.pubshares);
                        group["recovery"] = recovery_json(&c.recovery, &g.threshold_pubkey);
                        group
                    }),
                    "sign": c.sign.as_ref().map(|s| json!({
                        "ssid": hex(&s.ssid),
                        "stage": s.stage.name(),
                        "msg": msg_json(&s.msg),
                        "tweaks": tweaks_json(&s.tweaks),
                        "key": hex(&compress_point_bip340(&s.signing_key)),
                        "request": s.request,
                        "nonces": s.nonces.keys().collect::<Vec<_>>(),
                        "package": s.package,
                        "signers": s.signers,
                        "partials": s.partials.keys().collect::<Vec<_>>(),
                        "signature": s.signature,
                        "error": s.error,
                    })),
                })
            }
        }
    }
}

impl PDkg {
    /// Records a protocol failure. The driver is spent; the session has to
    /// be restarted.
    fn fail(&mut self, error: String) -> String {
        self.stage = Stage::Failed;
        self.driver = None;
        self.out = None;
        self.error = Some(error.clone());
        error
    }
}

impl PSign {
    /// Records a failure and drops the signer, wiping its secret nonce.
    fn fail(&mut self, error: String) -> String {
        self.stage = Stage::Failed;
        self.signer = None;
        self.out = None;
        self.error = Some(error.clone());
        error
    }
}

impl CDkg {
    fn fail(&mut self, error: String) -> String {
        self.stage = Stage::Failed;
        self.error = Some(error.clone());
        error
    }
}

impl CSign {
    fn fail(&mut self, error: String) -> String {
        self.stage = Stage::Failed;
        self.error = Some(error.clone());
        error
    }
}

// -------------------------------------------------------------------- helpers

fn random_bytes(rng: &mut Rng) -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rng(bytes.as_mut());
    bytes
}

/// Makes a host key: the hash of what the user added (dice rolls, coin flips,
/// a drawing), XORed with fresh device randomness when `rng` is given.
///
/// The XOR of two independent values is at least as hard to guess as the
/// better of them, so poor user input cannot weaken a key that has device
/// randomness in it, and good input covers for a weak random number
/// generator. With nothing added the key is the device randomness alone.
/// Without `rng` it is a function of the user input alone: the same input
/// always gives the same key.
fn host_scalar(
    mut rng: Option<&mut Rng>,
    dice: &[u8],
    coins: &[u8],
    drawing: &[u8],
) -> Zeroizing<Scalar> {
    // A value that is not a valid non-zero scalar is astronomically
    // unlikely; the counter makes the next attempt differ even then.
    for counter in 0u32.. {
        let mut hasher = tagged_hasher(TAG_HOST_KEY);
        for part in [dice, coins, drawing] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        hasher.update(counter.to_be_bytes());
        let mut bytes: Zeroizing<[u8; 32]> = Zeroizing::new(hasher.finalize().into());
        if let Some(rng) = rng.as_mut() {
            let random = random_bytes(rng);
            for (byte, r) in bytes.iter_mut().zip(random.iter()) {
                *byte ^= r;
            }
        }
        if let Ok(scalar) = parse_secret_scalar_from_bytes(bytes)
            && !bool::from(scalar.is_zero())
        {
            return Zeroizing::new(scalar);
        }
    }
    unreachable!("a valid scalar is found long before the counter runs out")
}

fn host_pubkey(secret: &Scalar) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * secret
}

/// Reads a public key given as x-only hex or as compressed SEC1 hex; BIP340
/// only looks at the x coordinate.
fn xonly_key(text: &str) -> Option<[u8; 32]> {
    let bytes = unhex(text).ok()?;
    let x = match bytes.len() {
        32 => &bytes[..],
        33 if matches!(bytes[0], 2 | 3) => &bytes[1..],
        _ => return None,
    };
    x.try_into().ok()
}

/// The point with the given x coordinate and an even y.
fn lift_x(xonly: &[u8; 32]) -> Option<ProjectivePoint> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(xonly);
    decompress_default(&compressed)
}

/// An exportable payload: its base64 text and a file name stem.
fn out(blob: &Blob, name: String) -> Value {
    json!({ "data": blob.to_text().as_str(), "name": name })
}

/// Short identifier of a public key for comparing by eye or by voice.
fn fingerprint(P: &ProjectivePoint) -> String {
    hex(&Sha256::digest(compress_default(P))[..4])
}

fn short(id: &SessionId) -> String {
    hex(&id[..4])
}

fn host_json(P: &ProjectivePoint) -> Value {
    json!({ "pubkey": hex(&compress_default(P)), "fp": fingerprint(P) })
}

fn group_json(
    t: usize,
    threshold_pubkey: &ProjectivePoint,
    pubshares: &[ProjectivePoint],
) -> Value {
    let xonly = compress_point_bip340(threshold_pubkey);
    json!({
        "t": t,
        "n": pubshares.len(),
        "pubkey": hex(&compress_default(threshold_pubkey)),
        "xonly": hex(&xonly),
        "fp": fingerprint(threshold_pubkey),
    })
}

/// What is actually signed: the SHA-256 digest of the message.
///
/// Messages always travel raw, so every signer sees what it approves, and
/// every party hashes for itself. A signature therefore never covers the
/// message bytes directly.
fn signed_digest(msg: &[u8]) -> Vec<u8> {
    Sha256::digest(msg).to_vec()
}

fn recovery_json(recovery: &Option<RecoveryData>, threshold_pubkey: &ProjectivePoint) -> Value {
    match recovery {
        Some(recovery) => out(
            &Blob::Recovery(recovery.clone()),
            format!("frost-recovery-{}", fingerprint(threshold_pubkey)),
        ),
        None => Value::Null,
    }
}

fn msg_json(msg: &[u8]) -> Value {
    let text = std::str::from_utf8(msg).ok().filter(|text| {
        !text.is_empty()
            && text
                .chars()
                .all(|c| !c.is_control() || c == '\n' || c == '\t' || c == '\r')
    });
    json!({
        "hex": hex(msg),
        "text": text,
        "base64": STANDARD.encode(msg),
        "len": msg.len(),
        "digest": hex(&signed_digest(msg)),
    })
}

fn tweaks_json(tweaks: &[Tweak]) -> Value {
    tweaks
        .iter()
        .map(|t| json!({ "value": hex(&t.value), "xonly": t.is_xonly }))
        .collect()
}

fn str_field<'a>(req: &'a Value, name: &str) -> Res<&'a str> {
    req[name]
        .as_str()
        .ok_or_else(|| format!("Missing field '{name}'."))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

fn unhex(text: &str) -> Result<Vec<u8>, ()> {
    let digits: Vec<u8> = text
        .trim()
        .trim_start_matches("0x")
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).map(|d| d as u8).ok_or(()))
        .collect::<Result<_, _>>()?;
    if !digits.len().is_multiple_of(2) {
        return Err(());
    }
    Ok(digits
        .chunks(2)
        .map(|pair| pair[0] << 4 | pair[1])
        .collect())
}

fn hex_array<const N: usize>(text: &str) -> Result<[u8; N], ()> {
    unhex(text)?.try_into().map_err(|_| ())
}

/// Library errors count participants from zero; the page shows them from one.
fn dkg_error(e: ChillDkgError) -> String {
    match e {
        ChillDkgError::FaultyParticipant {
            participant,
            message,
        } => format!("Participant #{} is faulty: {message}", participant + 1),
        ChillDkgError::FaultyParticipantOrCoordinator {
            participant,
            message,
        } => format!(
            "Participant #{} or the coordinator is faulty: {message}",
            participant + 1
        ),
        ChillDkgError::DuplicateHostPubkey {
            participant1,
            participant2,
        } => format!(
            "Participants #{} and #{} have the same host public key.",
            participant1 + 1,
            participant2 + 1
        ),
        ChillDkgError::InvalidHostPubkey { participant } => format!(
            "Participant #{} has an invalid host public key.",
            participant + 1
        ),
        ChillDkgError::InvalidSignatureInCertificate { participant } => format!(
            "Participant #{} has an invalid signature in the certificate.",
            participant + 1
        ),
        ChillDkgError::ThresholdOrCount => {
            "The threshold must be between 1 and the number of participants.".into()
        }
        other => capitalize(other.to_string()),
    }
}

fn sign_error(e: SignError) -> String {
    match e {
        SignError::InvalidContribution {
            participant,
            message,
        } => format!(
            "Participant #{} sent an invalid contribution: {message}. Start a new signing session without them.",
            participant + 1
        ),
        other => capitalize(other.to_string()),
    }
}

fn capitalize(mut text: String) -> String {
    if let Some(first) = text.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    text
}
